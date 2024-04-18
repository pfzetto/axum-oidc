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

The `OidcRpInitializedLogout`-extractor can be used to get the rp initialized logout uri.

Your OIDC-Client must be allowed to redirect to **every** subpath of your application base url.

# Examples
Take a look at the `examples` folder for examples.

# Older Versions
All versions on [crates.io](https://crates.io) are available as git tags.
Additonal all minor versions have their own branch (format `vX.Y` where `X` is the major and `Y` is the minor version) where bug fixes are implemented.
Examples for each version can be found there in the previously mentioned `examples` folder.

# Contributing
I'm happy about any contribution in any form.
Feel free to submit feature requests and bug reports using a GitHub Issue.
PR's are also appreciated.

# License
This Library is licensed under [LGPLv3](https://www.gnu.org/licenses/lgpl-3.0.en.html).

