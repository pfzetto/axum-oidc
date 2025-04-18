use basic::run;
#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let issuer = std::env::var("ISSUER").expect("ISSUER env variable");
    let client_id = std::env::var("CLIENT_ID").expect("CLIENT_ID env variable");
    let client_secret = std::env::var("CLIENT_SECRET").ok();
    run(issuer, client_id, client_secret).await
}
