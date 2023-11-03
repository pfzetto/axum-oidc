This Library allows using [OpenID Connect](https://openid.net/developers/how-connect-works/) with [axum](https://github.com/tokio-rs/axum). 
It authenticates the user with the OpenID Conenct Issuer and provides Extractors.

# Usage
The `OidcAuthLayer` must be loaded on any handler that might use the extractors.
The user won't be automatically logged in using this layer.
If a valid session is found, the extractors will return the correct value and fail otherwise.

The `OidcLoginLayer` should be loaded on any handler on which the user is supposed to be authenticated.
The User will be redirected to the OpenId Conect Issuer to authenticate.
The extractors will always return a value.

The `OidcClaims`-extractor can be used to get the OpenId Conenct Claims.
The `OidcAccessToken`-extractor can be used to get the OpenId Connect Access Token.

Your OIDC-Client must be allowed to redirect to **every** subpath of your application base url.

```rust
#[tokio::main]
async fn main() {

    let session_store = MemoryStore::default();
    let session_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_: BoxError| async {
            StatusCode::BAD_REQUEST
        }))
        .layer(SessionManagerLayer::new(session_store).with_same_site(SameSite::Lax));

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
                Uri::from_static("https://example.com"),
                "<issuer>".to_string(),
                "<client_id>".to_string(),
                "<client_secret>".to_owned(),
                vec![],
            ).await.unwrap(),
        );

    let app = Router::new()
        .route("/", get(|| async { "Hello, authenticated World!" }))
        .layer(oidc_login_service)
        .layer(oidc_auth_service)
        .layer(session_service);

    axum::Server::bind(&"[::]:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

# Example Projects
Here is a place for projects that are using this library.
- [zettoIT ARS - AudienceResponseSystem](https://git2.zettoit.eu/zettoit/ars) (by me)

# Contributing
I'm happy about any contribution in any form.
Feel free to submit feature requests and bug reports using a GitHub Issue.
PR's are also appreciated.

# License
This Library is licensed under [LGPLv3](https://www.gnu.org/licenses/lgpl-3.0.en.html).

