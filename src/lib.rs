#![doc = include_str!("../README.md")]

use std::str::FromStr;

use crate::error::Error;
use http::Uri;
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreClaimName, CoreClaimType, CoreClientAuthMethod,
        CoreErrorResponseType, CoreGenderClaim, CoreGrantType, CoreJsonWebKey, CoreJsonWebKeyType,
        CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
        CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseMode, CoreResponseType,
        CoreRevocableToken, CoreRevocationErrorResponse, CoreSubjectIdentifierType,
        CoreTokenIntrospectionResponse, CoreTokenType,
    },
    reqwest::async_http_client,
    ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, IdTokenFields, IssuerUrl, Nonce,
    PkceCodeVerifier, RefreshToken, StandardErrorResponse, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};

pub mod error;
mod extractor;
mod middleware;

pub use extractor::{OidcAccessToken, OidcClaims, OidcRpInitiatedLogout};
pub use middleware::{OidcAuthLayer, OidcAuthMiddleware, OidcLoginLayer, OidcLoginMiddleware};

const SESSION_KEY: &str = "axum-oidc";

pub trait AdditionalClaims: openidconnect::AdditionalClaims + Clone + Sync + Send {}

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

type ProviderMetadata = openidconnect::ProviderMetadata<
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
#[derive(Clone)]
pub struct OidcClient<AC: AdditionalClaims> {
    scopes: Vec<String>,
    client_id: String,
    client: Client<AC>,
    application_base_url: Uri,
    end_session_endpoint: Option<Uri>,
}

impl<AC: AdditionalClaims> OidcClient<AC> {
    pub async fn discover_new(
        application_base_url: Uri,
        issuer: String,
        client_id: String,
        client_secret: Option<String>,
        scopes: Vec<String>,
    ) -> Result<Self, Error> {
        let provider_metadata =
            ProviderMetadata::discover_async(IssuerUrl::new(issuer)?, async_http_client).await?;
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
        Ok(Self {
            scopes,
            client,
            client_id,
            application_base_url,
            end_session_endpoint,
        })
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
    session_state: String,
}

/// oidc session
#[derive(Serialize, Deserialize, Debug)]
struct OidcSession {
    nonce: Nonce,
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
    id_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

impl OidcSession {
    pub(crate) fn id_token<AC: AdditionalClaims>(&self) -> Option<IdToken<AC>> {
        self.id_token
            .as_ref()
            .map(|x| IdToken::<AC>::from_str(x).unwrap())
    }
    pub(crate) fn refresh_token(&self) -> Option<RefreshToken> {
        self.refresh_token
            .as_ref()
            .map(|x| RefreshToken::new(x.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdditionalProviderMetadata {
    end_session_endpoint: Option<String>,
}
impl openidconnect::AdditionalProviderMetadata for AdditionalProviderMetadata {}
