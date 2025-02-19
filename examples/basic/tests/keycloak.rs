use log::info;
use std::time::Duration;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;

use testcontainers::core::ExecCommand;
use testcontainers::{core::WaitFor, Image, ImageExt};

struct KeycloakImage;

impl Image for KeycloakImage {
    fn name(&self) -> &str {
        "quay.io/keycloak/keycloak"
    }

    fn tag(&self) -> &str {
        "latest"
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![]
    }
}

pub struct Keycloak {
    container: ContainerAsync<KeycloakImage>,
    realms: Vec<Realm>,
    url: String,
}

#[derive(Clone)]
pub struct Realm {
    pub name: String,
    pub clients: Vec<Client>,
    pub users: Vec<User>,
}

#[derive(Clone)]
pub struct Client {
    pub client_id: String,
    pub client_secret: Option<String>,
}

#[derive(Clone)]
pub struct User {
    pub username: String,
    pub email: String,
    pub firstname: String,
    pub lastname: String,
    pub password: String,
}

impl Keycloak {
    pub async fn start(realms: Vec<Realm>) -> Keycloak {
        info!("starting keycloak");

        let keycloak_image = KeycloakImage
            .with_cmd(["start-dev".to_string()])
            .with_env_var("KEYCLOAK_ADMIN", "admin")
            .with_env_var("KEYCLOAK_ADMIN_PASSWORD", "admin");
        let container = keycloak_image.start().await.unwrap();

        let keycloak = Self {
            url: format!(
                "http://127.0.0.1:{}",
                container.get_host_port_ipv4(8080).await.unwrap()
            ),
            container,
            realms,
        };

        let issuer = format!(
            "http://127.0.0.1:{}/realms/{}",
            keycloak.container.get_host_port_ipv4(8080).await.unwrap(),
            "test"
        );

        while reqwest::get(&issuer).await.is_err() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        keycloak.execute("/opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 --realm master --user admin --password admin".to_string()).await;

        for realm in keycloak.realms.iter() {
            keycloak.create_realm(&realm.name).await;
            for client in realm.clients.iter() {
                keycloak
                    .create_client(
                        &client.client_id,
                        client.client_secret.as_deref(),
                        &realm.name,
                    )
                    .await;
            }
            for user in realm.users.iter() {
                keycloak
                    .create_user(
                        &user.username,
                        &user.email,
                        &user.firstname,
                        &user.lastname,
                        &user.password,
                        &realm.name,
                    )
                    .await;
            }
        }

        keycloak
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    async fn create_realm(&self, name: &str) {
        self.execute(format!(
            "/opt/keycloak/bin/kcadm.sh create realms -s realm={} -s enabled=true",
            name
        ))
        .await;
    }

    async fn create_client(&self, client_id: &str, client_secret: Option<&str>, realm: &str) {
        if let Some(client_secret) = client_secret {
            self.execute(format!(
                r#"/opt/keycloak/bin/kcadm.sh create clients -r {} -f - << EOF
            {{
                "clientId": "{}",
                "secret": "{}",
                "redirectUris": ["*"]
            }}
            EOF
            "#,
                realm, client_id, client_secret
            ))
            .await;
        } else {
            self.execute(format!(
                r#"/opt/keycloak/bin/kcadm.sh create clients -r {} -f - << EOF
            {{
                "clientId": "{}",
                "redirectUris": ["*"]
            }}
            EOF
            "#,
                realm, client_id
            ))
            .await;
        }
    }

    async fn create_user(
        &self,
        username: &str,
        email: &str,
        firstname: &str,
        lastname: &str,
        password: &str,
        realm: &str,
    ) {
        let id = self.execute(
        format!(
            "/opt/keycloak/bin/kcadm.sh create users -r {} -s username={} -s enabled=true -s emailVerified=true -s email={} -s firstName={} -s lastName={}",
            realm, username, email, firstname, lastname
        ),
    )
    .await;
        self.execute(format!(
            "/opt/keycloak/bin/kcadm.sh set-password -r {} --username {} --new-password {}",
            realm, username, password
        ))
        .await;
        id
    }

    async fn execute(&self, cmd: String) {
        let mut result = self
            .container
            .exec(ExecCommand::new(
                ["/bin/sh", "-c", cmd.as_str()].iter().copied(),
            ))
            .await
            .unwrap();
        // collect stdout to wait until command completion
        let _output = String::from_utf8(result.stdout_to_vec().await.unwrap());
    }
}
