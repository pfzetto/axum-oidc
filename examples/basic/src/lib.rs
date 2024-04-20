use axum::{
    error_handling::HandleErrorLayer, http::Uri, response::IntoResponse, routing::get, Router,
};
use axum_oidc::{
    error::MiddlewareError, EmptyAdditionalClaims, OidcAuthLayer, OidcClaims, OidcLoginLayer,
    OidcRpInitiatedLogout,
};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_sessions::{
    cookie::{time::Duration, SameSite},
    Expiry, MemoryStore, SessionManagerLayer,
};

pub async fn run(
    app_url: String,
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
) {
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(Duration::seconds(120)));

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
        .route("/logout", get(logout))
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
    format!("Hello {}", claims.subject().as_str())
}

async fn maybe_authenticated(
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

async fn logout(logout: OidcRpInitiatedLogout) -> impl IntoResponse {
    logout.with_post_logout_redirect(Uri::from_static("https://pfzetto.de"))
}
