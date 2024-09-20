
use axum::{error_handling::HandleErrorLayer, routing::get};
use axum_oidc::EmptyAdditionalClaims;
use keycloak::Keycloak;
use utils::handle_axum_oidc_middleware_error;

mod keycloak;
mod utils;

#[tokio::test(flavor = "multi_thread")]
async fn basic_login_oidc() {
    let john = keycloak::User {
        username: "jojo".to_string(),
        email: "john.doe@example.com".to_string(),
        firstname: "john".to_string(),
        lastname: "doe".to_string(),
        password: "jopass".to_string(),
    };

    let basic_client = keycloak::Client {
        client_id: "axum-oidc-example-basic".to_string(),
        client_secret: Some("123456".to_string()),
        ..Default::default()
    };

    let realm_name = "test";

    let keycloak = Keycloak::start(vec![keycloak::Realm {
        name: realm_name.to_string(),
        clients: vec![basic_client.clone()],
        users: vec![], // Not used here, needed for id
    }])
    .await
    .unwrap();
    let id = keycloak.create_user(&john.username, &john.email, &john.firstname, &john.lastname, &john.password, realm_name).await;

    let keycloak_url = keycloak.url();
    let issuer = format!("{keycloak_url}/realms/{realm_name}");

    let login_service = tower::ServiceBuilder::new()
        .layer(HandleErrorLayer::new(handle_axum_oidc_middleware_error))
        .layer(axum_oidc::OidcLoginLayer::<EmptyAdditionalClaims>::new());

    let oidc_client = axum_oidc::OidcAuthLayer::<EmptyAdditionalClaims>::discover_client(
        axum::http::Uri::from_static("http://localhost:3000"),
        issuer,
        basic_client.client_id,
        basic_client.client_secret,
        vec![]
    )
    .await
    .expect("Cannot create OIDC client");

    let auth_service = tower::ServiceBuilder::new()
        .layer(HandleErrorLayer::new(handle_axum_oidc_middleware_error))
        .layer(oidc_client);

    let session_store = tower_sessions::MemoryStore::default();
    let session_layer = tower_sessions::SessionManagerLayer::new(session_store)
        .with_same_site(tower_sessions::cookie::SameSite::None)
        .with_expiry(tower_sessions::Expiry::OnInactivity(
            tower_sessions::cookie::time::Duration::minutes(120),
        ));

    let app = axum::Router::new()
            .route("/foo", get(utils::authenticated))
            .layer(login_service)
            .route("/bar", get(utils::maybe_authenticated))
            .layer(auth_service)
            .layer(session_layer);
        

    let server = axum_test::TestServerConfig::builder()
        .save_cookies()
        .http_transport()
        .build_server(app)
        .unwrap();

    let client = reqwest::ClientBuilder::new()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // GET /bar
    let response = server.get("/bar").await;
    response.assert_status(axum_test::http::StatusCode::OK);
    response.assert_text("Hello anon!");

    // GET /foo
    let response = server.get("/foo").await;
    response.assert_status(axum_test::http::StatusCode::TEMPORARY_REDIRECT);
    let url = utils::extract_location_header_testresponse(response).unwrap();

    // GET keycloak/auth
    let response = client.get(url).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let html = response.text().await.unwrap();
    let url_regex = regex::Regex::new(r#"action="([^"]+)""#).unwrap();
    let url = url_regex.captures(&html).unwrap().get(1).unwrap().as_str();
    let params = [("username", "jojo"), ("password", "jopass")];

    // POST keycloak/auth
    let response = client.post(url).form(&params).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    let url = utils::extract_location_header_response(response).unwrap();
    let url = url.replace("http://localhost:3000", ""); // Remove http://localhost:3000

    // GET /foo-callback
    let response = server.get(&url).await;
    response.assert_status(axum_test::http::StatusCode::TEMPORARY_REDIRECT);
    response.assert_header("Location", "http://localhost:3000/foo");

    // GET /foo
    let response = server.get("/foo").await;
    response.assert_status(axum_test::http::StatusCode::OK);
    response.assert_text(format!("Hello {id}"));

    // GET /bar
    let response = server.get("/bar").await;
    response.assert_status(axum_test::http::StatusCode::OK);
    response.assert_text(format!("Hello {id}! You are already logged in from another Handler."));
}
