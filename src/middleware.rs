use std::{
    marker::PhantomData,
    str::FromStr,
    task::{Context, Poll},
};

use axum::{
    extract::Query,
    response::{IntoResponse, Redirect},
};
use axum_core::{extract::FromRequestParts, response::Response};
use futures_util::future::BoxFuture;
use http::{Request, Uri};
use tower_layer::Layer;
use tower_service::Service;
use tower_sessions::Session;

use openidconnect::{
    core::CoreAuthenticationFlow, reqwest::async_http_client, AccessTokenHash, AuthorizationCode,
    CsrfToken, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};

use crate::{
    error::{Error, MiddlewareError},
    extractor::{OidcAccessToken, OidcClaims},
    util::strip_oidc_from_path,
    AdditionalClaims, BoxError, IdToken, OidcClient, OidcQuery, OidcSession, SESSION_KEY,
};

/// Layer for the [OidcLoginMiddleware].
#[derive(Clone, Default)]
pub struct OidcLoginLayer<AC>
where
    AC: AdditionalClaims,
{
    additional: PhantomData<AC>,
}

impl<AC: AdditionalClaims> OidcLoginLayer<AC> {
    pub fn new() -> Self {
        Self {
            additional: PhantomData,
        }
    }
}

impl<I, AC> Layer<I> for OidcLoginLayer<AC>
where
    AC: AdditionalClaims,
{
    type Service = OidcLoginMiddleware<I, AC>;

    fn layer(&self, inner: I) -> Self::Service {
        OidcLoginMiddleware {
            inner,
            additional: PhantomData,
        }
    }
}

/// This middleware forces the user to be authenticated and redirects the user to the OpenID Connect
/// Issuer to authenticate. This Middleware needs to be loaded afer [OidcAuthMiddleware].
#[derive(Clone)]
pub struct OidcLoginMiddleware<I, AC>
where
    AC: AdditionalClaims,
{
    inner: I,
    additional: PhantomData<AC>,
}

impl<I, AC, B> Service<Request<B>> for OidcLoginMiddleware<I, AC>
where
    I: Service<Request<B>, Response = Response> + Send + 'static + Clone,
    I::Error: Send + Into<BoxError>,
    I::Future: Send + 'static,
    AC: AdditionalClaims,
    B: Send + 'static,
{
    type Response = I::Response;
    type Error = MiddlewareError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|e| MiddlewareError::NextMiddleware(e.into()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        if request.extensions().get::<OidcAccessToken>().is_some() {
            Box::pin(async move {
                let response: Response = inner
                    .call(request)
                    .await
                    .map_err(|e| MiddlewareError::NextMiddleware(e.into()))?;
                return Ok(response);
            })
        } else {
            Box::pin(async move {
                let (mut parts, _) = request.into_parts();

                let mut oidcclient: OidcClient<AC> = parts
                    .extensions
                    .get()
                    .cloned()
                    .ok_or(MiddlewareError::AuthMiddlewareNotFound)?;

                let query = Query::<OidcQuery>::from_request_parts(&mut parts, &())
                    .await
                    .ok();

                let session = parts
                    .extensions
                    .get::<Session>()
                    .ok_or(MiddlewareError::SessionNotFound)?;
                let login_session: Option<OidcSession> =
                    session.get(SESSION_KEY).map_err(MiddlewareError::from)?;

                let handler_uri =
                    strip_oidc_from_path(oidcclient.application_base_url.clone(), &parts.uri)?;

                oidcclient.client = oidcclient
                    .client
                    .set_redirect_uri(RedirectUrl::new(handler_uri.to_string())?);

                if let (Some(mut login_session), Some(query)) = (login_session, query) {
                    if login_session.csrf_token.secret() != &query.state {
                        return Err(MiddlewareError::CsrfTokenInvalid);
                    }

                    let token_response = oidcclient
                        .client
                        .exchange_code(AuthorizationCode::new(query.code.to_string()))
                        // Set the PKCE code verifier.
                        .set_pkce_verifier(PkceCodeVerifier::new(
                            login_session.pkce_verifier.secret().to_string(),
                        ))
                        .request_async(async_http_client)
                        .await?;

                    // Extract the ID token claims after verifying its authenticity and nonce.
                    let id_token = token_response
                        .id_token()
                        .ok_or(MiddlewareError::IdTokenMissing)?;
                    let claims = id_token
                        .claims(&oidcclient.client.id_token_verifier(), &login_session.nonce)?;

                    // Verify the access token hash to ensure that the access token hasn't been substituted for
                    // another user's.
                    if let Some(expected_access_token_hash) = claims.access_token_hash() {
                        let actual_access_token_hash = AccessTokenHash::from_token(
                            token_response.access_token(),
                            &id_token.signing_alg()?,
                        )?;
                        if actual_access_token_hash != *expected_access_token_hash {
                            return Err(MiddlewareError::AccessTokenHashInvalid);
                        }
                    }

                    login_session.id_token = Some(id_token.to_string());
                    login_session.access_token =
                        Some(token_response.access_token().secret().to_string());

                    session.insert(SESSION_KEY, login_session).unwrap();

                    Ok(Redirect::temporary(&handler_uri.to_string()).into_response())
                } else {
                    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
                    let (auth_url, csrf_token, nonce) = {
                        let mut auth = oidcclient.client.authorize_url(
                            CoreAuthenticationFlow::AuthorizationCode,
                            CsrfToken::new_random,
                            Nonce::new_random,
                        );

                        for scope in oidcclient.scopes.iter() {
                            auth = auth.add_scope(Scope::new(scope.to_string()));
                        }

                        auth.set_pkce_challenge(pkce_challenge).url()
                    };

                    let oidc_session = OidcSession {
                        nonce,
                        csrf_token,
                        pkce_verifier,
                        id_token: None,
                        access_token: None,
                    };

                    session.insert(SESSION_KEY, oidc_session).unwrap();

                    Ok(Redirect::temporary(auth_url.as_str()).into_response())
                }
            })
        }
    }
}

/// Layer for the [OidcAuthMiddleware].
#[derive(Clone)]
pub struct OidcAuthLayer<AC>
where
    AC: AdditionalClaims,
{
    client: OidcClient<AC>,
}

impl<AC: AdditionalClaims> OidcAuthLayer<AC> {
    pub fn new(client: OidcClient<AC>) -> Self {
        Self { client }
    }

    pub async fn discover_client(
        application_base_url: Uri,
        issuer: String,
        client_id: String,
        client_secret: Option<String>,
        scopes: Vec<String>,
    ) -> Result<Self, Error> {
        Ok(Self {
            client: OidcClient::<AC>::discover_new(
                application_base_url,
                issuer,
                client_id,
                client_secret,
                scopes,
            )
            .await?,
        })
    }
}

impl<I, AC> Layer<I> for OidcAuthLayer<AC>
where
    AC: AdditionalClaims,
{
    type Service = OidcAuthMiddleware<I, AC>;

    fn layer(&self, inner: I) -> Self::Service {
        OidcAuthMiddleware {
            inner,
            client: self.client.clone(),
        }
    }
}

/// This middleware checks if the cached session is valid and injects the Claims, the AccessToken
/// and the OidcClient in the request. This middleware needs to be loaded for every handler that is
/// using on of the Extractors. This middleware **doesn't force a user to be
/// authenticated**.
#[derive(Clone)]
pub struct OidcAuthMiddleware<I, AC>
where
    AC: AdditionalClaims,
{
    inner: I,
    client: OidcClient<AC>,
}

impl<I, AC, B> Service<Request<B>> for OidcAuthMiddleware<I, AC>
where
    I: Service<Request<B>> + Send + 'static + Clone,
    I::Response: IntoResponse + Send,
    I::Error: Send + Into<BoxError>,
    I::Future: Send + 'static,
    AC: AdditionalClaims,
    B: Send + 'static,
{
    type Response = Response;
    type Error = MiddlewareError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|e| MiddlewareError::NextMiddleware(e.into()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);
        let mut oidcclient = self.client.clone();
        Box::pin(async move {
            let (mut parts, body) = request.into_parts();

            let session = parts
                .extensions
                .get::<Session>()
                .ok_or(MiddlewareError::SessionNotFound)?;
            let login_session: Option<OidcSession> =
                session.get(SESSION_KEY).map_err(MiddlewareError::from)?;

            let handler_uri =
                strip_oidc_from_path(oidcclient.application_base_url.clone(), &parts.uri)?;

            oidcclient.client = oidcclient
                .client
                .set_redirect_uri(RedirectUrl::new(handler_uri.to_string())?);

            if let Some(OidcSession {
                nonce,
                csrf_token: _,
                pkce_verifier: _,
                id_token: Some(id_token),
                access_token,
            }) = &login_session
            {
                let id_token = IdToken::<AC>::from_str(&id_token).unwrap();
                if let Ok(claims) = id_token.claims(&oidcclient.client.id_token_verifier(), nonce) {
                    parts.extensions.insert(OidcClaims(claims.clone()));
                    parts
                        .extensions
                        .insert(OidcAccessToken(access_token.clone().unwrap_or_default()));
                }
            }

            parts.extensions.insert(oidcclient);

            let request = Request::from_parts(parts, body);
            let response: Response = inner
                .call(request)
                .await
                .map_err(|e| MiddlewareError::NextMiddleware(e.into()))?
                .into_response();
            return Ok(response);
        })
    }
}
