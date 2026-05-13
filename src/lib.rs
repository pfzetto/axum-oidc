#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(warnings)]
#![doc = include_str!("../README.md")]

use std::sync::Arc;

use arc_swap::ArcSwap;
use http::Uri;
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreClaimName, CoreClaimType, CoreClientAuthMethod,
        CoreErrorResponseType, CoreGenderClaim, CoreGrantType, CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm,
        CoreResponseMode, CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
        CoreSubjectIdentifierType, CoreTokenIntrospectionResponse, CoreTokenType,
    },
    AccessToken, Audience, AuthenticationContextClass, ClientId, ClientSecret, CsrfToken,
    EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet, GenderClaim,
    IdTokenFields, IssuerUrl, Nonce, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope,
    StandardClaims, StandardErrorResponse, StandardTokenResponse,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::error::Error;

pub mod builder;
pub mod error;
mod extractor;
mod handler;
mod middleware;

pub use extractor::{OidcAccessToken, OidcClaims, OidcRpInitiatedLogout, OidcUserInfo};
pub use handler::handle_oidc_redirect;
pub use middleware::{OidcAuthLayer, OidcAuthMiddleware, OidcLoginLayer, OidcLoginMiddleware};
pub use openidconnect;

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
    >,
    CoreTokenType,
>;

pub type IdToken<AZ> = openidconnect::IdToken<
    AZ,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

type Client<
    AC,
    HasAuthUrl = EndpointSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointMaybeSet,
    HasUserInfoUrl = EndpointMaybeSet,
> = openidconnect::Client<
    AC,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    OidcTokenResponse<AC>,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
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
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// OpenID Connect Client
///
/// The inner [`Client`] is held behind an [`ArcSwap`] so that its cached
/// metadata — most importantly the JWKS used for ID token signature
/// verification — can be replaced at runtime via
/// [`OidcClient::rediscover`]. All clones of this `OidcClient` (including
/// the ones held by `OidcAuthLayer` / `OidcAuthMiddleware`) share the same
/// swap cell, so a single refresh call propagates to every middleware
/// instance.
#[derive(Clone)]
pub struct OidcClient<AC: AdditionalClaims> {
    scopes: Vec<Scope>,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    redirect_url: Uri,
    client: Arc<ArcSwap<Client<AC>>>,
    http_client: reqwest::Client,
    end_session_endpoint: Option<Uri>,
    auth_context_class: Option<AuthenticationContextClass>,
    untrusted_audiences: Vec<Audience>,
}

impl<AC: AdditionalClaims> OidcClient<AC> {
    /// Re-run OIDC discovery and atomically swap the cached metadata.
    ///
    /// The new [`openidconnect::JsonWebKeySet`] takes effect for every
    /// subsequent request handled by middleware that holds a clone of
    /// this client — useful for picking up provider key rotation without
    /// restarting the process. Spawn a background task that calls this on
    /// a timer, e.g. every 15 minutes:
    ///
    /// ```ignore
    /// let client = oidc_client.clone();
    /// tokio::spawn(async move {
    ///     let mut tick = tokio::time::interval(std::time::Duration::from_secs(900));
    ///     tick.tick().await; // skip the immediate first tick
    ///     loop {
    ///         tick.tick().await;
    ///         if let Err(e) = client.rediscover(issuer.clone()).await {
    ///             tracing::warn!("OIDC rediscovery failed: {e}");
    ///         }
    ///     }
    /// });
    /// ```
    ///
    /// `end_session_endpoint` is intentionally not refreshed; in practice
    /// providers do not change it during key rotation, and keeping it
    /// stable avoids breaking in-flight RP-initiated logout flows.
    pub async fn rediscover(&self, issuer: IssuerUrl) -> Result<(), Error> {
        let provider_metadata = ProviderMetadata::discover_async(issuer, &self.http_client).await?;
        let new_client = Client::from_provider_metadata(
            provider_metadata,
            self.client_id.clone(),
            self.client_secret.clone(),
        )
        .set_redirect_uri(RedirectUrl::new(self.redirect_url.to_string())?);
        self.client.store(Arc::new(new_client));
        Ok(())
    }
}

/// an empty struct to be used as the default type for the additional claims generic
#[derive(Deserialize, Serialize, Debug, Clone, Copy, Default)]
pub struct EmptyAdditionalClaims {}
impl AdditionalClaims for EmptyAdditionalClaims {}
impl openidconnect::AdditionalClaims for EmptyAdditionalClaims {}

/// oidc session
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "AC: Serialize + DeserializeOwned")]
struct OidcSession<AC: AdditionalClaims, GC: GenderClaim> {
    nonce: Nonce,
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
    authenticated: Option<AuthenticatedSession<AC, GC>>,
    refresh_token: Option<RefreshToken>,
    redirect_url: Box<str>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "AC: Serialize + DeserializeOwned")]
struct AuthenticatedSession<AC: AdditionalClaims, GC: GenderClaim> {
    id_token: IdToken<AC>,
    access_token: AccessToken,
    user_info: UserInfoClaims<AC, GC>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "AC: Serialize + DeserializeOwned")]
pub struct UserInfoClaims<AC: AdditionalClaims, GC: GenderClaim> {
    pub issuer: Option<openidconnect::IssuerUrl>,
    pub audiences: Option<Vec<Audience>>,
    pub standard_claims: StandardClaims<GC>,
    pub additional_claims: AC,
}

impl<AC, GC> From<openidconnect::UserInfoClaims<AC, GC>> for UserInfoClaims<AC, GC>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    fn from(value: openidconnect::UserInfoClaims<AC, GC>) -> Self {
        Self {
            issuer: value.issuer().cloned(),
            audiences: value.audiences().cloned(),
            standard_claims: value.standard_claims().clone(),
            additional_claims: value.additional_claims().clone(),
        }
    }
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
