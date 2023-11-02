**This crate is still under construction**

This Library allows using [OpenID Connect](https://openid.net/developers/how-connect-works/) with [axum](https://github.com/tokio-rs/axum). It provides two modes, described below.

# Operating Modes
## Client Mode
In Client mode, the user visits the axum server with a web browser. The user gets redirected to and authenticated with the Issuer.

## Token Mode
In Token mode, the another system is using the access token of the user to authenticate against the axum server.

# License
This Library is licensed under [LGPLv3](https://www.gnu.org/licenses/lgpl-3.0.en.html).

