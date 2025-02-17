#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(warnings)]
#![doc = include_str!("../README.md")]

use crate::error::Error;
use http::Uri;
use oidc_client_builder::{IsUnset, SetClient, SetClientId, SetEndSessionEndpoint, State};
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreClaimName, CoreClaimType, CoreClientAuthMethod,
        CoreErrorResponseType, CoreGenderClaim, CoreGrantType, CoreJsonWebKey, CoreJsonWebKeyType,
        CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
        CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType, CoreRevocableToken,
        CoreRevocationErrorResponse, CoreSubjectIdentifierType, CoreTokenIntrospectionResponse,
        CoreTokenType,
    },
    AccessToken, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, HttpRequest,
    HttpResponse, IdTokenFields, IssuerUrl, Nonce, PkceCodeVerifier, RefreshToken,
    StandardErrorResponse, StandardTokenResponse,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub mod error;
mod extractor;
mod middleware;

pub use extractor::{OidcAccessToken, OidcClaims, OidcRpInitiatedLogout};
pub use middleware::{OidcAuthLayer, OidcAuthMiddleware, OidcLoginLayer, OidcLoginMiddleware};

const SESSION_KEY: &str = "axum-oidc";

pub trait AdditionalClaims:
    openidconnect::AdditionalClaims + Clone + Sync + Send + Serialize + DeserializeOwned
{
}

type OidcTokenResponse<AC> = StandardTokenResponse<
    IdTokenFields<
        AC,
        EmptyExtraTokenFields,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
    >,
    CoreTokenType,
>;

pub type IdToken<AZ> = openidconnect::IdToken<
    AZ,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

type Client<AC> = openidconnect::Client<
    AC,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    OidcTokenResponse<AC>,
    CoreTokenType,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
>;

pub type ProviderMetadata = openidconnect::ProviderMetadata<
    AdditionalProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// OpenID Connect Client
#[derive(Clone, bon::Builder)]
pub struct OidcClient<AC: AdditionalClaims> {
    #[builder(field)]
    http_client: reqwest::Client,

    scopes: Vec<String>,
    client: Client<AC>,
    client_id: String,
    application_base_url: Uri,
    end_session_endpoint: Option<Uri>,
}

type SetFinal<AC, S> = OidcClientBuilder<AC, SetClientId<SetClient<SetEndSessionEndpoint<S>>>>;

impl<AC: AdditionalClaims, S: State> OidcClientBuilder<AC, S> {
    pub fn http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = http_client;
        self
    }

    /// set `end_session_endpoint` and initialize a `client` from an existing [`ProviderMetadata`].
    pub fn with_provider_metadata(
        self,
        provider_metadata: ProviderMetadata,
        client_id: String,
        client_secret: Option<String>,
    ) -> Result<SetFinal<AC, S>, Error>
    where
        S::EndSessionEndpoint: IsUnset,
        S::Client: IsUnset,
        S::ClientId: IsUnset,
    {
        let end_session_endpoint = provider_metadata
            .additional_metadata()
            .end_session_endpoint
            .clone()
            .map(Uri::from_maybe_shared)
            .transpose()
            .map_err(Error::InvalidEndSessionEndpoint)?;
        let client = Client::from_provider_metadata(
            provider_metadata,
            ClientId::new(client_id.clone()),
            client_secret.map(ClientSecret::new),
        );

        Ok(self
            .maybe_end_session_endpoint(end_session_endpoint)
            .client(client)
            .client_id(client_id))
    }

    /// create a new [`OidcClient`] by fetching the required information from the
    /// `/.well-known/openid-configuration` endpoint of the issuer.
    pub async fn discover_new_with_client(
        self,
        issuer: String,
        client_id: String,
        client_secret: Option<String>,
    ) -> Result<SetFinal<AC, S>, Error>
    where
        S::EndSessionEndpoint: IsUnset,
        S::Client: IsUnset,
        S::ClientId: IsUnset,
    {
        let http_client = &self.http_client.clone();

        // modified version of `openidconnect::reqwest::async_client::async_http_client`.
        let async_http_client = |request: HttpRequest| async move {
            let mut request_builder = http_client
                .request(request.method, request.url.as_str())
                .body(request.body);
            for (name, value) in &request.headers {
                request_builder = request_builder.header(name.as_str(), value.as_bytes());
            }
            let request = request_builder
                .build()
                .map_err(openidconnect::reqwest::Error::Reqwest)?;

            let response = http_client
                .execute(request)
                .await
                .map_err(openidconnect::reqwest::Error::Reqwest)?;

            let status_code = response.status();
            let headers = response.headers().to_owned();
            let chunks = response
                .bytes()
                .await
                .map_err(openidconnect::reqwest::Error::Reqwest)?;
            Ok(HttpResponse {
                status_code,
                headers,
                body: chunks.to_vec(),
            })
        };

        let provider_metadata =
            ProviderMetadata::discover_async(IssuerUrl::new(issuer)?, async_http_client).await?;

        self.with_provider_metadata(provider_metadata, client_id, client_secret)
    }
}

impl<AC: AdditionalClaims> OidcClient<AC> {
    /// create a new [`OidcClient`] from an existing [`ProviderMetadata`].
    pub fn from_provider_metadata(
        provider_metadata: ProviderMetadata,
        application_base_url: Uri,
        client_id: String,
        client_secret: Option<String>,
        scopes: Vec<String>,
    ) -> Result<Self, Error> {
        Ok(Self::builder()
            .scopes(scopes)
            .application_base_url(application_base_url)
            .with_provider_metadata(provider_metadata, client_id, client_secret)?
            .build())
    }
    /// create a new [`OidcClient`] from an existing [`ProviderMetadata`].
    pub fn from_provider_metadata_and_client(
        provider_metadata: ProviderMetadata,
        application_base_url: Uri,
        client_id: String,
        client_secret: Option<String>,
        scopes: Vec<String>,
        http_client: reqwest::Client,
    ) -> Result<Self, Error> {
        Ok(Self::builder()
            .http_client(http_client)
            .scopes(scopes)
            .application_base_url(application_base_url)
            .with_provider_metadata(provider_metadata, client_id, client_secret)?
            .build())
    }

    /// create a new [`OidcClient`] by fetching the required information from the
    /// `/.well-known/openid-configuration` endpoint of the issuer.
    pub async fn discover_new(
        application_base_url: Uri,
        issuer: String,
        client_id: String,
        client_secret: Option<String>,
        scopes: Vec<String>,
    ) -> Result<Self, Error> {
        let client = reqwest::Client::default();
        Self::discover_new_with_client(
            application_base_url,
            issuer,
            client_id,
            client_secret,
            scopes,
            &client,
        )
        .await
    }

    /// create a new [`OidcClient`] by fetching the required information from the
    /// `/.well-known/openid-configuration` endpoint of the issuer using the provided
    /// `reqwest::Client`.
    pub async fn discover_new_with_client(
        application_base_url: Uri,
        issuer: String,
        client_id: String,
        client_secret: Option<String>,
        scopes: Vec<String>,
        //TODO remove borrow with next breaking version
        client: &reqwest::Client,
    ) -> Result<Self, Error> {
        Ok(Self::builder()
            .http_client(client.clone())
            .scopes(scopes)
            .application_base_url(application_base_url)
            .discover_new_with_client(issuer, client_id, client_secret)
            .await?
            .build())
    }
}

/// an empty struct to be used as the default type for the additional claims generic
#[derive(Deserialize, Serialize, Debug, Clone, Copy, Default)]
pub struct EmptyAdditionalClaims {}
impl AdditionalClaims for EmptyAdditionalClaims {}
impl openidconnect::AdditionalClaims for EmptyAdditionalClaims {}

/// response data of the openid issuer after login
#[derive(Debug, Deserialize)]
struct OidcQuery {
    code: String,
    state: String,
    #[allow(dead_code)]
    session_state: Option<String>,
}

/// oidc session
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "AC: Serialize + DeserializeOwned")]
struct OidcSession<AC: AdditionalClaims> {
    nonce: Nonce,
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
    authenticated: Option<AuthenticatedSession<AC>>,
    refresh_token: Option<RefreshToken>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "AC: Serialize + DeserializeOwned")]
struct AuthenticatedSession<AC: AdditionalClaims> {
    id_token: IdToken<AC>,
    access_token: AccessToken,
}

/// additional metadata that is discovered on client creation via the
/// `.well-knwon/openid-configuration` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdditionalProviderMetadata {
    end_session_endpoint: Option<String>,
}
impl openidconnect::AdditionalProviderMetadata for AdditionalProviderMetadata {}

/// response extension flag to signal the [`OidcAuthLayer`] that the session should be cleared.
#[derive(Clone, Copy)]
pub struct ClearSessionFlag;
