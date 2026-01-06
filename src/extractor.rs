use std::{borrow::Cow, convert::Infallible, ops::Deref};

use crate::{error::ExtractorError, AdditionalClaims, ClearSessionFlag, UserInfoClaims};
use axum::response::Redirect;
use axum_core::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    response::IntoResponse,
};
use http::{request::Parts, uri::PathAndQuery, Uri};
use openidconnect::{core::CoreGenderClaim, ClientId, IdTokenClaims};

/// Extractor for the OpenID Connect Claims.
///
/// This Extractor will only return the Claims when the cached session is valid and [`crate::middleware::OidcAuthMiddleware`] is loaded.
#[derive(Clone, Debug)]
pub struct OidcClaims<AC: AdditionalClaims>(pub IdTokenClaims<AC, CoreGenderClaim>);

impl<S, AC> FromRequestParts<S> for OidcClaims<AC>
where
    S: Send + Sync,
    AC: AdditionalClaims,
{
    type Rejection = ExtractorError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(ExtractorError::Unauthorized)
    }
}

impl<S, AC> OptionalFromRequestParts<S> for OidcClaims<AC>
where
    S: Send + Sync,
    AC: AdditionalClaims,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned())
    }
}

impl<AC: AdditionalClaims> Deref for OidcClaims<AC> {
    type Target = IdTokenClaims<AC, CoreGenderClaim>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<AC> AsRef<IdTokenClaims<AC, CoreGenderClaim>> for OidcClaims<AC>
where
    AC: AdditionalClaims,
{
    fn as_ref(&self) -> &IdTokenClaims<AC, CoreGenderClaim> {
        &self.0
    }
}

/// Extractor for the OpenID Connect Access Token.
///
/// This Extractor will only return the Access Token when the cached session is valid and [`crate::middleware::OidcAuthMiddleware`] is loaded.
#[derive(Clone)]
pub struct OidcAccessToken(pub String);

impl<S> FromRequestParts<S> for OidcAccessToken
where
    S: Send + Sync,
{
    type Rejection = ExtractorError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(ExtractorError::Unauthorized)
    }
}

impl<S> OptionalFromRequestParts<S> for OidcAccessToken
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned())
    }
}

impl Deref for OidcAccessToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for OidcAccessToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Extractor for the [OpenID Connect RP-Initialized Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) URL
///
/// This Extractor will only succed when the cached session is valid, [`crate::middleware::OidcAuthMiddleware`] is loaded and the issuer supports RP-Initialized Logout.
#[derive(Clone)]
pub struct OidcRpInitiatedLogout {
    pub(crate) end_session_endpoint: Uri,
    pub(crate) id_token_hint: Box<str>,
    pub(crate) client_id: ClientId,
    pub(crate) post_logout_redirect_uri: Option<Uri>,
    pub(crate) state: Option<String>,
}

impl OidcRpInitiatedLogout {
    /// set uri that the user is redirected to after logout.
    /// This uri must be in the allowed by issuer.
    pub fn with_post_logout_redirect(mut self, uri: Uri) -> Self {
        self.post_logout_redirect_uri = Some(uri);
        self
    }
    /// set the state parameter that is appended as a query to the post logout redirect uri.
    pub fn with_state(mut self, state: String) -> Self {
        self.state = Some(state);
        self
    }
    /// get the uri that the client needs to access for logout. This does **NOT** delete the
    /// session in axum-oidc. You should use the [`ClearSessionFlag`] responder or include
    /// [`OidcRpInitiatedLogout`] in the response extensions
    pub fn uri(&self) -> Result<Uri, http::Error> {
        let mut parts = self.end_session_endpoint.clone().into_parts();

        let query = {
            let mut query: Vec<(&str, Cow<'_, str>)> = Vec::with_capacity(4);
            query.push(("id_token_hint", Cow::Borrowed(&self.id_token_hint)));
            query.push(("client_id", Cow::Borrowed(&self.client_id)));

            if let Some(post_logout_redirect_uri) = &self.post_logout_redirect_uri {
                query.push((
                    "post_logout_redirect_uri",
                    Cow::Owned(post_logout_redirect_uri.to_string()),
                ));
            }
            if let Some(state) = &self.state {
                query.push(("state", Cow::Borrowed(state)));
            }

            query
                .into_iter()
                .map(|(k, v)| format!("{}={}", k, urlencoding::encode(&v)))
                .collect::<Vec<_>>()
                .join("&")
        };

        let path_and_query = match parts.path_and_query {
            Some(path_and_query) => {
                PathAndQuery::from_maybe_shared(format!("{}?{}", path_and_query.path(), query))
            }
            None => PathAndQuery::from_maybe_shared(format!("?{}", query)),
        };
        parts.path_and_query = Some(path_and_query?);

        Ok(Uri::from_parts(parts)?)
    }
}

impl<S> FromRequestParts<S> for OidcRpInitiatedLogout
where
    S: Send + Sync,
{
    type Rejection = ExtractorError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        match parts
            .extensions
            .get::<Option<Self>>()
            .cloned()
            .ok_or(ExtractorError::Unauthorized)?
        {
            Some(this) => Ok(this),
            None => Err(ExtractorError::RpInitiatedLogoutNotSupported),
        }
    }
}

impl<S> OptionalFromRequestParts<S> for OidcRpInitiatedLogout
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Option<Self>>().cloned().flatten())
    }
}

impl IntoResponse for OidcRpInitiatedLogout {
    /// redirect to the logout uri and signal the [`crate::middleware::OidcAuthMiddleware`] that
    /// the session should be cleared
    fn into_response(self) -> axum_core::response::Response {
        if let Ok(uri) = self.uri() {
            let mut response = Redirect::temporary(&uri.to_string()).into_response();
            response.extensions_mut().insert(ClearSessionFlag);
            response
        } else {
            ExtractorError::FailedToCreateRpInitiatedLogoutUri.into_response()
        }
    }
}

/// Extractor for the OpenID Connect User Info Claims.
///
/// This Extractor will only return the User Info Claims when the cached session is valid and [`crate::middleware::OidcAuthMiddleware`] is loaded.
#[derive(Clone, Debug)]
pub struct OidcUserInfo<AC: AdditionalClaims>(pub UserInfoClaims<AC, CoreGenderClaim>);

impl<S, AC> FromRequestParts<S> for OidcUserInfo<AC>
where
    S: Send + Sync,
    AC: AdditionalClaims,
{
    type Rejection = ExtractorError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(ExtractorError::Unauthorized)
    }
}

impl<S, AC> OptionalFromRequestParts<S> for OidcUserInfo<AC>
where
    S: Send + Sync,
    AC: AdditionalClaims,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned())
    }
}

impl<AC: AdditionalClaims> Deref for OidcUserInfo<AC> {
    type Target = UserInfoClaims<AC, CoreGenderClaim>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<AC> AsRef<UserInfoClaims<AC, CoreGenderClaim>> for OidcUserInfo<AC>
where
    AC: AdditionalClaims,
{
    fn as_ref(&self) -> &UserInfoClaims<AC, CoreGenderClaim> {
        &self.0
    }
}
