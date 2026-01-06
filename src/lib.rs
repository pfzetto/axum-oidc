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
    AccessToken, Audience, AuthenticationContextClass, ClientId, CsrfToken, EmptyExtraTokenFields,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, GenderClaim, IdTokenFields, Nonce,
    PkceCodeVerifier, RefreshToken, Scope, StandardClaims, StandardErrorResponse,
    StandardTokenResponse,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

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
#[derive(Clone)]
pub struct OidcClient<AC: AdditionalClaims> {
    scopes: Vec<Scope>,
    client_id: ClientId,
    client: Client<AC>,
    http_client: reqwest::Client,
    end_session_endpoint: Option<Uri>,
    auth_context_class: Option<AuthenticationContextClass>,
    untrusted_audiences: Vec<Audience>,
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
