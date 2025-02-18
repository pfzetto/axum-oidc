#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(warnings)]
#![doc = include_str!("../README.md")]

use http::Uri;
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreClaimName, CoreClaimType, CoreClientAuthMethod,
        CoreErrorResponseType, CoreGenderClaim, CoreGrantType, CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm,
        CoreResponseMode, CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
        CoreSubjectIdentifierType, CoreTokenIntrospectionResponse, CoreTokenType,
    },
    AccessToken, CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet,
    IdTokenFields, Nonce, PkceCodeVerifier, RefreshToken, StandardErrorResponse,
    StandardTokenResponse,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub mod builder;
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
#[derive(Clone)]
pub struct OidcClient<AC: AdditionalClaims> {
    scopes: Vec<Box<str>>,
    oidc_request_parameters: Vec<Box<str>>,
    client_id: Box<str>,
    client: Client<AC>,
    http_client: reqwest::Client,
    application_base_url: Uri,
    end_session_endpoint: Option<Uri>,
    auth_context_class: Option<Box<str>>,
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
