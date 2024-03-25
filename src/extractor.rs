use std::{borrow::Cow, ops::Deref};

use crate::{error::ExtractorError, AdditionalClaims};
use async_trait::async_trait;
use axum::response::Redirect;
use axum_core::{
    extract::FromRequestParts,
    response::{IntoResponse, Response},
};
use http::{request::Parts, uri::PathAndQuery, Uri};
use openidconnect::{core::CoreGenderClaim, IdTokenClaims};

/// Extractor for the OpenID Connect Claims.
///
/// This Extractor will only return the Claims when the cached session is valid and [crate::middleware::OidcAuthMiddleware] is loaded.
#[derive(Clone)]
pub struct OidcClaims<AC: AdditionalClaims>(pub IdTokenClaims<AC, CoreGenderClaim>);

#[async_trait]
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
/// This Extractor will only return the Access Token when the cached session is valid and [crate::middleware::OidcAuthMiddleware] is loaded.
#[derive(Clone)]
pub struct OidcAccessToken(pub String);

#[async_trait]
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

impl Deref for OidcAccessToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for OidcAccessToken {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone)]
pub struct OidcRpInitiatedLogout {
    pub(crate) end_session_endpoint: Uri,
    pub(crate) id_token_hint: String,
    pub(crate) client_id: String,
    pub(crate) post_logout_redirect_uri: Option<Uri>,
    pub(crate) state: Option<String>,
}

impl OidcRpInitiatedLogout {
    pub fn with_post_logout_redirect(mut self, uri: Uri) -> Self {
        self.post_logout_redirect_uri = Some(uri);
        self
    }
    pub fn with_state(mut self, state: String) -> Self {
        self.state = Some(state);
        self
    }
    pub fn uri(self) -> Uri {
        let mut parts = self.end_session_endpoint.into_parts();

        let query = {
            let mut query = Vec::with_capacity(4);
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
                .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v.as_str())))
                .collect::<Vec<_>>()
                .join("&")
        };

        let path_and_query = match parts.path_and_query {
            Some(path_and_query) => {
                PathAndQuery::from_maybe_shared(format!("{}?{}", path_and_query.path(), query))
            }
            None => PathAndQuery::from_maybe_shared(format!("?{}", query)),
        };
        parts.path_and_query = Some(path_and_query.unwrap());

        Uri::from_parts(parts).unwrap()
    }
}
#[async_trait]
impl<S> FromRequestParts<S> for OidcRpInitiatedLogout
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

#[async_trait]
impl IntoResponse for OidcRpInitiatedLogout {
    fn into_response(self) -> Response {
        Redirect::temporary(&self.uri().to_string()).into_response()
    }
}
