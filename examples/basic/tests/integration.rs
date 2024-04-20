mod keycloak;

use headless_chrome::Browser;
use log::info;
use testcontainers::*;

use crate::keycloak::{Client, Keycloak, Realm, User};

#[tokio::test(flavor = "multi_thread")]
async fn first() {
    env_logger::init();

    let docker = clients::Cli::default();

    let alice = User {
        username: "alice".to_string(),
        email: "alice@example.com".to_string(),
        firstname: "alice".to_string(),
        lastname: "doe".to_string(),
        password: "alice".to_string(),
    };

    let basic_client = Client {
        client_id: "axum-oidc-example-basic".to_string(),
        client_secret: Some("123456".to_string()),
    };

    let keycloak = Keycloak::start(
        vec![Realm {
            name: "test".to_string(),
            users: vec![alice.clone()],
            clients: vec![basic_client.clone()],
        }],
        &docker,
    )
    .await;

    info!("starting basic example app");

    let app_url = "http://127.0.0.1:8080/";
    let app_handle = tokio::spawn(basic::run(
        app_url.to_string(),
        format!("{}/realms/test", keycloak.url()),
        basic_client.client_id.to_string(),
        basic_client.client_secret.clone(),
    ));

    info!("starting browser");

    let browser = Browser::default().unwrap();
    let tab = browser.new_tab().unwrap();

    tab.navigate_to(&format!("{}bar", app_url)).unwrap();
    let body = tab
        .wait_for_xpath(r#"/html/body/pre"#)
        .unwrap()
        .get_inner_text()
        .unwrap();
    assert_eq!(body, "Hello anon!");

    tab.navigate_to(&format!("{}foo", app_url)).unwrap();
    let username = tab.wait_for_xpath(r#"//*[@id="username"]"#).unwrap();
    username.type_into(&alice.username).unwrap();
    let password = tab.wait_for_xpath(r#"//*[@id="password"]"#).unwrap();
    password.type_into(&alice.password).unwrap();
    let submit = tab.wait_for_xpath(r#"//*[@id="kc-login"]"#).unwrap();
    submit.click().unwrap();

    let body = tab
        .wait_for_xpath(r#"/html/body/pre"#)
        .unwrap()
        .get_inner_text()
        .unwrap();
    assert!(body.starts_with("Hello ") && body.contains('-'));

    tab.navigate_to(&format!("{}bar", app_url)).unwrap();
    let body = tab
        .wait_for_xpath(r#"/html/body/pre"#)
        .unwrap()
        .get_inner_text()
        .unwrap();
    assert!(body.contains("! You are already logged in from another Handler."));

    tab.navigate_to(&format!("{}logout", app_url)).unwrap();
    tab.wait_until_navigated().unwrap();

    tab.navigate_to(&format!("{}bar", app_url)).unwrap();
    let body = tab
        .wait_for_xpath(r#"/html/body/pre"#)
        .unwrap()
        .get_inner_text()
        .unwrap();
    assert_eq!(body, "Hello anon!");

    tab.navigate_to(&format!("{}foo", app_url)).unwrap();
    tab.wait_until_navigated().unwrap();
    tab.find_element_by_xpath(r#"//*[@id="username"]"#).unwrap();

    tab.close(true).unwrap();
    app_handle.abort();
}
