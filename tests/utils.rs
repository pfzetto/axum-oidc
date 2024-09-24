use axum::response::IntoResponse;
use axum_oidc::{EmptyAdditionalClaims, OidcClaims};


pub async fn authenticated(claims: OidcClaims<EmptyAdditionalClaims>) -> impl IntoResponse {
    format!("Hello {}", claims.subject().as_str())
}

pub async fn maybe_authenticated(
    claims: Option<OidcClaims<EmptyAdditionalClaims>>,
) -> impl IntoResponse {
    if let Some(claims) = claims {
        format!(
            "Hello {}! You are already logged in from another Handler.",
            claims.subject().as_str()
        )
    } else {
        "Hello anon!".to_string()
    }
}

pub async fn handle_axum_oidc_middleware_error(
    e: axum_oidc::error::MiddlewareError,
) -> axum::http::Response<axum::body::Body> {
    e.into_response()
}

pub fn extract_location_header_testresponse(response: axum_test::TestResponse) -> Option<String> {
    Some(
        response
            .headers()
            .get("Location")?
            .to_str()
            .ok()?
            .to_string(),
    )
}

pub fn extract_location_header_response(response: reqwest::Response) -> Option<String> {
    Some(
        response
            .headers()
            .get("Location")?
            .to_str()
            .ok()?
            .to_string(),
    )
}
