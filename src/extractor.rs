use crate::{error::ExtractorError, AdditionalClaims};
use async_trait::async_trait;
use axum_core::extract::FromRequestParts;
use http::request::Parts;
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
