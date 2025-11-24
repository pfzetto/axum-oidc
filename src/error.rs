use axum_core::{response::IntoResponse, BoxError};
use http::{
    uri::{InvalidUri, InvalidUriParts},
    StatusCode,
};
use openidconnect::{core::CoreErrorResponseType, StandardErrorResponse};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExtractorError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("rp initiated logout not supported by issuer")]
    RpInitiatedLogoutNotSupported,

    #[error("could not build rp initiated logout uri")]
    FailedToCreateRpInitiatedLogoutUri,
}

#[derive(Debug, Error)]
pub enum MiddlewareError {
    #[error("configuration: {0:?}")]
    Configuration(#[from] openidconnect::ConfigurationError),

    #[error("access token hash invalid")]
    AccessTokenHashInvalid,

    #[error("csrf token invalid")]
    CsrfTokenInvalid,

    #[error("id token missing")]
    IdTokenMissing,

    #[error("signing: {0:?}")]
    Signing(#[from] openidconnect::SigningError),

    #[error("signature verification: {0:?}")]
    Signature(#[from] openidconnect::SignatureVerificationError),

    #[error("claims verification: {0:?}")]
    ClaimsVerification(#[from] openidconnect::ClaimsVerificationError),

    #[error("user info retrieval: {0:?}")]
    UserInfoRetrieval(
        #[from]
        openidconnect::UserInfoError<
            openidconnect::HttpClientError<openidconnect::reqwest::Error>,
        >,
    ),

    #[error("url parsing: {0:?}")]
    UrlParsing(#[from] openidconnect::url::ParseError),

    #[error("uri parsing: {0:?}")]
    UriParsing(#[from] InvalidUri),

    #[error("uri parts parsing: {0:?}")]
    UriPartsParsing(#[from] InvalidUriParts),

    #[error("request token: {0:?}")]
    RequestToken(
        #[from]
        openidconnect::RequestTokenError<
            openidconnect::HttpClientError<openidconnect::reqwest::Error>,
            StandardErrorResponse<CoreErrorResponseType>,
        >,
    ),

    #[error("session error: {0:?}")]
    Session(#[from] tower_sessions::session::Error),

    #[error("session not found")]
    SessionNotFound,

    #[error("next middleware")]
    NextMiddleware(#[from] BoxError),

    #[error("auth middleware not found")]
    AuthMiddlewareNotFound,

    #[error("original url not found")]
    OriginalUrlNotFound,
}

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("redirect handler accessed without valid session, session cookie missing?")]
    RedirectedWithoutSession,

    #[error("csrf token invalid")]
    CsrfTokenInvalid,

    #[error("id token missing")]
    IdTokenMissing,

    #[error("access token hash invalid")]
    AccessTokenHashInvalid,

    #[error("signing: {0:?}")]
    Signing(#[from] openidconnect::SigningError),

    #[error("signature verification: {0:?}")]
    Signature(#[from] openidconnect::SignatureVerificationError),

    #[error("session error: {0:?}")]
    Session(#[from] tower_sessions::session::Error),

    #[error("configuration: {0:?}")]
    Configuration(#[from] openidconnect::ConfigurationError),

    #[error("request token: {0:?}")]
    RequestToken(
        #[from]
        openidconnect::RequestTokenError<
            openidconnect::HttpClientError<openidconnect::reqwest::Error>,
            StandardErrorResponse<CoreErrorResponseType>,
        >,
    ),

    #[error("claims verification: {0:?}")]
    ClaimsVerification(#[from] openidconnect::ClaimsVerificationError),
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("url parsing: {0:?}")]
    UrlParsing(#[from] openidconnect::url::ParseError),

    #[error("invalid end_session_endpoint uri: {0:?}")]
    InvalidEndSessionEndpoint(http::uri::InvalidUri),

    #[error("discovery: {0:?}")]
    Discovery(
        #[from]
        openidconnect::DiscoveryError<
            openidconnect::HttpClientError<openidconnect::reqwest::Error>,
        >,
    ),

    #[error("extractor: {0:?}")]
    Extractor(#[from] ExtractorError),

    #[error("extractor: {0:?}")]
    Middleware(#[from] MiddlewareError),

    #[error("handler: {0:?}")]
    Handler(#[from] HandlerError),
}

impl IntoResponse for ExtractorError {
    fn into_response(self) -> axum_core::response::Response {
        match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
            Self::RpInitiatedLogoutNotSupported => {
                (StatusCode::INTERNAL_SERVER_ERROR, "intenal server error").into_response()
            }
            Self::FailedToCreateRpInitiatedLogoutUri => {
                (StatusCode::INTERNAL_SERVER_ERROR, "intenal server error").into_response()
            }
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum_core::response::Response {
        tracing::error!(error = self.to_string());
        (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
    }
}

impl IntoResponse for MiddlewareError {
    fn into_response(self) -> axum_core::response::Response {
        tracing::error!(error = self.to_string());
        (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
    }
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> axum_core::response::Response {
        tracing::error!(error = self.to_string());
        (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
    }
}
