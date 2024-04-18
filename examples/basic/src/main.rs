use axum::{
    error_handling::HandleErrorLayer, http::Uri, response::IntoResponse, routing::get, Router,
};
use axum_oidc::{
    error::MiddlewareError, EmptyAdditionalClaims, OidcAuthLayer, OidcClaims, OidcLoginLayer,
};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_sessions::{cookie::SameSite, MemoryStore, SessionManagerLayer};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let app_url = std::env::var("APP_URL").expect("APP_URL env variable");
    let issuer = std::env::var("ISSUER").expect("ISSUER env variable");
    let client_id = std::env::var("CLIENT_ID").expect("CLIENT_ID env variable");
    let client_secret = std::env::var("CLIENT_SECRET").ok();

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store).with_same_site(SameSite::Lax);

    let oidc_login_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|e: MiddlewareError| async {
            e.into_response()
        }))
        .layer(OidcLoginLayer::<EmptyAdditionalClaims>::new());

    let oidc_auth_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|e: MiddlewareError| async {
            e.into_response()
        }))
        .layer(
            OidcAuthLayer::<EmptyAdditionalClaims>::discover_client(
                Uri::from_maybe_shared(app_url).expect("valid APP_URL"),
                issuer,
                client_id,
                client_secret,
                vec![],
            )
            .await
            .unwrap(),
        );

    let app = Router::new()
        .route("/foo", get(authenticated))
        .layer(oidc_login_service)
        .route("/bar", get(maybe_authenticated))
        .layer(oidc_auth_service)
        .layer(session_layer);

    let listener = TcpListener::bind("[::]:8080").await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

async fn authenticated(claims: OidcClaims<EmptyAdditionalClaims>) -> impl IntoResponse {
    format!("Hello {}", claims.0.subject().as_str())
}

async fn maybe_authenticated(
    claims: Option<OidcClaims<EmptyAdditionalClaims>>,
) -> impl IntoResponse {
    if let Some(claims) = claims {
        format!(
            "Hello {}! You are already logged in from another Handler.",
            claims.0.subject().as_str()
        )
    } else {
        "Hello anon!".to_string()
    }
}
