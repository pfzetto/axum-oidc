use std::{
    marker::PhantomData,
    task::{Context, Poll},
};

use axum::{
    extract::OriginalUri,
    response::{IntoResponse, Redirect},
};
use axum_core::response::Response;
use futures_util::future::BoxFuture;
use http::{request::Parts, Request};
use tower_layer::Layer;
use tower_service::Service;
use tower_sessions::Session;

use openidconnect::{
    core::{CoreAuthenticationFlow, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey},
    AccessToken, AccessTokenHash, CsrfToken, IdTokenClaims, IdTokenVerifier, Nonce,
    NonceVerifier as _, OAuth2TokenResponse, PkceCodeChallenge, RefreshToken,
    RequestTokenError::ServerResponse,
    Scope, TokenResponse, UserInfoClaims,
};

use crate::{
    error::MiddlewareError,
    extractor::{OidcAccessToken, OidcClaims, OidcRpInitiatedLogout, OidcUserInfo},
    AdditionalClaims, AuthenticatedSession, BoxError, ClearSessionFlag, IdToken, OidcClient,
    OidcSession, SESSION_KEY,
};

/// Layer for the [`OidcLoginMiddleware`].
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
/// Issuer to authenticate. This Middleware needs to be loaded afer [`OidcAuthMiddleware`].
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
            // the OidcAuthMiddleware had a valid id token
            Box::pin(async move {
                let response: Response = inner
                    .call(request)
                    .await
                    .map_err(|e| MiddlewareError::NextMiddleware(e.into()))?;
                Ok(response)
            })
        } else {
            // no valid id token or refresh token was found and the user has to login
            Box::pin(async move {
                let (parts, _) = request.into_parts();

                let oidcclient: OidcClient<AC> = parts
                    .extensions
                    .get()
                    .cloned()
                    .ok_or(MiddlewareError::AuthMiddlewareNotFound)?;

                let session = parts
                    .extensions
                    .get::<Session>()
                    .ok_or(MiddlewareError::SessionNotFound)?;

                let redirect_url = parts
                    .extensions
                    .get::<OriginalUri>()
                    .ok_or(MiddlewareError::OriginalUrlNotFound)?;

                let redirect_url = if let Some(query) = redirect_url.query() {
                    redirect_url.path().to_string() + "?" + query
                } else {
                    redirect_url.path().to_string()
                };
                // generate a login url and redirect the user to it

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

                    if let Some(acr) = oidcclient.auth_context_class {
                        auth = auth.add_auth_context_value(acr);
                    }

                    auth.set_pkce_challenge(pkce_challenge).url()
                };

                let oidc_session = OidcSession::<AC, CoreGenderClaim> {
                    nonce,
                    csrf_token,
                    pkce_verifier,
                    authenticated: None,
                    refresh_token: None,
                    redirect_url: redirect_url.into(),
                };

                session.insert(SESSION_KEY, oidc_session).await?;

                Ok(Redirect::to(auth_url.as_str()).into_response())
            })
        }
    }
}

/// Layer for the [`OidcAuthMiddleware`].
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
}
impl<AC: AdditionalClaims> From<OidcClient<AC>> for OidcAuthLayer<AC> {
    fn from(value: OidcClient<AC>) -> Self {
        Self::new(value)
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
        let oidcclient = self.client.clone();

        Box::pin(async move {
            let (mut parts, body) = request.into_parts();

            let session = parts
                .extensions
                .get::<Session>()
                .ok_or(MiddlewareError::SessionNotFound)?
                .clone();
            let mut login_session: Option<OidcSession<AC, CoreGenderClaim>> = session
                .get(SESSION_KEY)
                .await
                .map_err(MiddlewareError::from)?;

            if let Some(login_session) = &mut login_session {
                let id_token_claims = login_session.authenticated.as_ref().and_then(|session| {
                    let nonce = login_session.nonce.clone();
                    session
                        .id_token
                        .claims(
                            &oidcclient
                                .client
                                .id_token_verifier()
                                .set_other_audience_verifier_fn(|audience| {
                                    // Return false (reject) if audience is in list of untrusted audiences
                                    !oidcclient.untrusted_audiences.contains(audience)
                                }),
                            // Accept tokens without a nonce (common after token refresh)
                            |claims_nonce: Option<&Nonce>| match claims_nonce {
                                Some(_) => nonce.verify(claims_nonce),
                                None => Ok(()),
                            },
                        )
                        .ok()
                        .cloned()
                        .map(|claims| (session, claims))
                });

                if let Some((session, claims)) = id_token_claims {
                    // stored id token is valid and can be used
                    insert_extensions(&mut parts, claims.clone(), &oidcclient, session);
                } else if let Some(refresh_token) = login_session.refresh_token.as_ref() {
                    // session is expired but can be refreshed using the refresh_token
                    if let Some((claims, authenticated_session, refresh_token)) =
                        try_refresh_token(&oidcclient, refresh_token, &login_session.nonce).await?
                    {
                        insert_extensions(&mut parts, claims, &oidcclient, &authenticated_session);
                        login_session.authenticated = Some(authenticated_session);

                        if let Some(refresh_token) = refresh_token {
                            login_session.refresh_token = Some(refresh_token);
                        }
                    };

                    // save refreshed session or delete it when the token couldn't be refreshed
                    let session = parts
                        .extensions
                        .get::<Session>()
                        .ok_or(MiddlewareError::SessionNotFound)?;

                    session.insert(SESSION_KEY, login_session).await?;
                }
            }

            parts.extensions.insert(oidcclient);

            let request = Request::from_parts(parts, body);
            let response: Response = inner
                .call(request)
                .await
                .map_err(|e| MiddlewareError::NextMiddleware(e.into()))?
                .into_response();

            let has_logout_ext = response.extensions().get::<ClearSessionFlag>().is_some();
            if let (true, Some(mut login_session)) = (has_logout_ext, login_session) {
                login_session.authenticated = None;
                login_session.refresh_token = None;
                session.insert(SESSION_KEY, login_session).await?;
            }

            Ok(response)
        })
    }
}

/// insert all extensions that are used by the extractors
fn insert_extensions<AC: AdditionalClaims>(
    parts: &mut Parts,
    claims: IdTokenClaims<AC, CoreGenderClaim>,
    client: &OidcClient<AC>,
    authenticated_session: &AuthenticatedSession<AC, CoreGenderClaim>,
) {
    parts.extensions.insert(OidcClaims(claims));
    parts
        .extensions
        .insert(OidcUserInfo(authenticated_session.user_info.clone()));
    parts.extensions.insert(OidcAccessToken(
        authenticated_session.access_token.secret().to_string(),
    ));
    let rp_initiated_logout = client
        .end_session_endpoint
        .as_ref()
        .map(|end_session_endpoint| OidcRpInitiatedLogout {
            end_session_endpoint: end_session_endpoint.clone(),
            id_token_hint: authenticated_session.id_token.to_string().into(),
            client_id: client.client_id.clone(),
            post_logout_redirect_uri: None,
            state: None,
        });
    parts.extensions.insert(rp_initiated_logout);
}

/// Verify the access token hash to ensure that the access token hasn't been substituted for
/// another user's.
/// Returns `Ok` when access token is valid
fn validate_access_token_hash<AC: AdditionalClaims>(
    id_token: &IdToken<AC>,
    id_token_verifier: IdTokenVerifier<CoreJsonWebKey>,
    access_token: &AccessToken,
    claims: &IdTokenClaims<AC, CoreGenderClaim>,
) -> Result<(), MiddlewareError> {
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            access_token,
            id_token.signing_alg()?,
            id_token.signing_key(&id_token_verifier)?,
        )?;
        if actual_access_token_hash == *expected_access_token_hash {
            Ok(())
        } else {
            Err(MiddlewareError::AccessTokenHashInvalid)
        }
    } else {
        Ok(())
    }
}

pub(crate) async fn get_user_claims<AC: AdditionalClaims>(
    client: &OidcClient<AC>,
    access_token: AccessToken,
) -> Result<UserInfoClaims<AC, CoreGenderClaim>, MiddlewareError> {
    client
        .client
        .user_info(access_token, None)
        .map_err(MiddlewareError::Configuration)?
        .request_async(&client.http_client)
        .await
        .map_err(|e| e.into())
}

async fn try_refresh_token<AC: AdditionalClaims>(
    client: &OidcClient<AC>,
    refresh_token: &RefreshToken,
    nonce: &Nonce,
) -> Result<
    Option<(
        IdTokenClaims<AC, CoreGenderClaim>,
        AuthenticatedSession<AC, CoreGenderClaim>,
        Option<RefreshToken>,
    )>,
    MiddlewareError,
> {
    let mut refresh_request = client.client.exchange_refresh_token(refresh_token)?;

    for scope in client.scopes.iter() {
        refresh_request = refresh_request.add_scope(Scope::new(scope.to_string()));
    }

    match refresh_request.request_async(&client.http_client).await {
        Ok(token_response) => {
            // Extract the ID token claims after verifying its authenticity and nonce.
            let id_token = token_response
                .id_token()
                .ok_or(MiddlewareError::IdTokenMissing)?;
            let id_token_verifier = client
                .client
                .id_token_verifier()
                .set_other_audience_verifier_fn(|audience|
                    // Return false (reject) if audience is in list of untrusted audiences
                    !client.untrusted_audiences.contains(audience));
            let claims = id_token.claims(&id_token_verifier, |claims_nonce: Option<&Nonce>| {
                match claims_nonce {
                    Some(_) => nonce.verify(claims_nonce),
                    None => Ok(()),
                }
            })?;

            validate_access_token_hash(
                id_token,
                id_token_verifier,
                token_response.access_token(),
                claims,
            )?;

            let access_token = token_response.access_token().clone();

            let user_claims = get_user_claims(client, access_token.clone()).await?;

            let authenticated_session = AuthenticatedSession {
                id_token: id_token.clone(),
                access_token,
                user_info: user_claims.into(),
            };

            Ok(Some((
                claims.clone(),
                authenticated_session,
                token_response.refresh_token().cloned(),
            )))
        }
        Err(ServerResponse(e)) if *e.error() == CoreErrorResponseType::InvalidGrant => {
            // Refresh failed, refresh_token most likely expired or
            // invalid, the session can be considered lost
            Ok(None)
        }
        Err(err) => Err(err.into()),
    }
}
