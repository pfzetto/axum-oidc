This example is a basic web application to demonstrate the features of the `axum-oidc`-crate.
It has three endpoints:
- `/logout` - Logout of the current session using `OIDC RP-Initiated Logout`.
- `/foo` - A handler that only can be accessed when logged in.
- `/bar` - A handler that can be accessed logged out and logged in. It will greet the user with their name if they are logged in.

# Running the Example
## Dependencies
You will need a running OpenID Connect capable issuer like [Keycloak](https://www.keycloak.org/getting-started/getting-started-docker) and a valid client for the issuer.

You can take a look at the `tests/`-folder to see how the automated keycloak deployment for the integration tests work.

## Setup Environment
Create a `.env`-file that contains the following keys:
```
APP_URL=http://127.0.0.1:8080
ISSUER=<your-issuer>
CLIENT_ID=<your-client-id>
CLIENT_SECRET=<your-client-secret>
```
## Run the application
`RUST_LOG=debug cargo run`
