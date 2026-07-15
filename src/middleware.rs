use std::{
    marker::PhantomData,
    task::{Context, Poll},
};

use axum::{
    extract::OriginalUri,
    response::{IntoResponse, Redirect},
};
use axum_core::{extract::FromRequestParts, response::Response};
use futures_util::future::BoxFuture;
use http::{request::Parts, Request};
use tower_layer::Layer;
use tower_service::Service;

use openidconnect::{
    core::{CoreAuthenticationFlow, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey},
    AccessToken, AccessTokenHash, IdTokenClaims, IdTokenVerifier, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, RefreshToken,
    RequestTokenError::ServerResponse,
    Scope, TokenResponse, UserInfoClaims,
};

use crate::{
    error::MiddlewareError,
    extractor::{OidcAccessToken, OidcClaims, OidcRpInitiatedLogout, OidcUserInfo},
    AdditionalClaims, AuthenticatedSession, BoxError, ClearSessionFlag, IdToken, OidcClient,
    OidcSession, OidcSessionInner, PendingOidcSession, Session,
};

/// Layer for the [`OidcLoginMiddleware`].
#[derive(Default)]
pub struct OidcLoginLayer<AC, S>
where
    AC: AdditionalClaims,
    S: Session<AC>,
{
    additional: PhantomData<AC>,
    session: PhantomData<S>,
}

impl<AC: AdditionalClaims, S: Session<AC>> OidcLoginLayer<AC, S> {
    pub fn new() -> Self {
        Self {
            additional: PhantomData,
            session: PhantomData,
        }
    }
}

impl<AC: AdditionalClaims, S: Session<AC>> Clone for OidcLoginLayer<AC, S> {
    fn clone(&self) -> Self {
        Self {
            additional: PhantomData,
            session: PhantomData,
        }
    }
}

impl<I, AC, S> Layer<I> for OidcLoginLayer<AC, S>
where
    AC: AdditionalClaims,
    S: Session<AC>,
{
    type Service = OidcLoginMiddleware<I, AC, S>;

    fn layer(&self, inner: I) -> Self::Service {
        OidcLoginMiddleware {
            inner,
            additional: PhantomData,
            session: PhantomData,
        }
    }
}

/// This middleware forces the user to be authenticated and redirects the user to the OpenID Connect
/// Issuer to authenticate. This Middleware needs to be loaded afer [`OidcAuthMiddleware`].
pub struct OidcLoginMiddleware<I, AC, S>
where
    AC: AdditionalClaims,
    S: Session<AC>,
{
    inner: I,
    additional: PhantomData<AC>,
    session: PhantomData<S>,
}

impl<I: Clone, AC: AdditionalClaims, S: Session<AC>> Clone for OidcLoginMiddleware<I, AC, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            additional: PhantomData,
            session: PhantomData,
        }
    }
}

impl<I, AC, B, S> Service<Request<B>> for OidcLoginMiddleware<I, AC, S>
where
    I: Service<Request<B>, Response = Response> + Send + 'static + Clone,
    I::Error: Send + Into<BoxError>,
    I::Future: Send + 'static,
    AC: AdditionalClaims,
    B: Send + 'static,
    S: Session<AC> + Send + FromRequestParts<()>,
    S::Error: Send + 'static,
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
                let (mut parts, _) = request.into_parts();

                let oidcclient: OidcClient<AC> = parts
                    .extensions
                    .get()
                    .cloned()
                    .ok_or(MiddlewareError::AuthMiddlewareNotFound)?;

                let mut session = S::from_request_parts(&mut parts, &())
                    .await
                    .map_err(|_| MiddlewareError::SessionNotFound)?;

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
                    let inner_client = oidcclient.client.load();
                    let state_generator = oidcclient.state_generator.clone();
                    let mut auth = inner_client.authorize_url(
                        CoreAuthenticationFlow::AuthorizationCode,
                        move || state_generator(),
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

                let oidc_session = OidcSession(OidcSessionInner::Pending(PendingOidcSession {
                    nonce,
                    csrf_token,
                    pkce_verifier,
                    redirect_url: redirect_url.into(),
                }));

                session
                    .set(oidc_session)
                    .await
                    .map_err(|x| MiddlewareError::Session(Box::new(x)))?;

                Ok(Redirect::to(auth_url.as_str()).into_response())
            })
        }
    }
}

/// Layer for the [`OidcAuthMiddleware`].
pub struct OidcAuthLayer<AC, S>
where
    AC: AdditionalClaims,
    S: Session<AC>,
{
    client: OidcClient<AC>,
    session: PhantomData<S>,
}

impl<AC: AdditionalClaims, S: Session<AC>> Clone for OidcAuthLayer<AC, S> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            session: PhantomData,
        }
    }
}

impl<AC: AdditionalClaims, S: Session<AC>> OidcAuthLayer<AC, S> {
    pub fn new(client: OidcClient<AC>) -> Self {
        Self {
            client,
            session: PhantomData,
        }
    }
}
impl<AC: AdditionalClaims, S: Session<AC>> From<OidcClient<AC>> for OidcAuthLayer<AC, S> {
    fn from(value: OidcClient<AC>) -> Self {
        Self::new(value)
    }
}

impl<I, AC, S> Layer<I> for OidcAuthLayer<AC, S>
where
    AC: AdditionalClaims,
    S: Session<AC>,
{
    type Service = OidcAuthMiddleware<I, AC, S>;

    fn layer(&self, inner: I) -> Self::Service {
        OidcAuthMiddleware {
            inner,
            client: self.client.clone(),
            session: PhantomData,
        }
    }
}

/// This middleware checks if the cached session is valid and injects the Claims, the AccessToken
/// and the OidcClient in the request. This middleware needs to be loaded for every handler that is
/// using on of the Extractors. This middleware **doesn't force a user to be
/// authenticated**.
pub struct OidcAuthMiddleware<I, AC, S>
where
    AC: AdditionalClaims,
    S: Session<AC>,
{
    inner: I,
    client: OidcClient<AC>,
    session: PhantomData<S>,
}

impl<I: Clone, AC: AdditionalClaims, S: Session<AC>> Clone for OidcAuthMiddleware<I, AC, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            client: self.client.clone(),
            session: PhantomData,
        }
    }
}

impl<I, AC, B, S> Service<Request<B>> for OidcAuthMiddleware<I, AC, S>
where
    I: Service<Request<B>> + Send + 'static + Clone,
    I::Response: IntoResponse + Send,
    I::Error: Send + Into<BoxError>,
    I::Future: Send + 'static,
    AC: AdditionalClaims,
    B: Send + 'static,
    S: Session<AC> + Send + FromRequestParts<()>,
    S::Error: Send + 'static,
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

            let mut session = S::from_request_parts(&mut parts, &())
                .await
                .map_err(|_| MiddlewareError::SessionNotFound)?;

            let login_session: OidcSession<AC, CoreGenderClaim> = session
                .get()
                .await
                .map_err(|x| MiddlewareError::Session(Box::new(x)))?;

            if let OidcSession(OidcSessionInner::Authenticated(mut login_session)) = login_session {
                let inner_client = oidcclient.client.load();
                let id_token_claims = {
                    login_session
                        .authenticated
                        .id_token
                        .claims(
                            &inner_client
                                .id_token_verifier()
                                .set_other_audience_verifier_fn(|audience| {
                                    // Return false (reject) if audience is in list of untrusted audiences
                                    !oidcclient.untrusted_audiences.contains(audience)
                                }),
                            // nonce was verified when transitioning from `OidcSession::Pending` to `OidcSession::Authenticated`
                            |_: Option<&Nonce>| Ok(()),
                        )
                        .ok()
                        .cloned()
                };

                if let Some(claims) = id_token_claims {
                    // stored id token is valid and can be used
                    insert_extensions(
                        &mut parts,
                        claims.clone(),
                        &oidcclient,
                        &login_session.authenticated,
                    );
                } else if let Some(refresh_token) = login_session.refresh_token.as_ref() {
                    // session is expired but can be refreshed using the refresh_token
                    let refresh_res = try_refresh_token(&oidcclient, refresh_token).await?;
                    if let Some((claims, authenticated_session, refresh_token)) = refresh_res {
                        insert_extensions(&mut parts, claims, &oidcclient, &authenticated_session);
                        login_session.authenticated = authenticated_session;

                        if let Some(refresh_token) = refresh_token {
                            login_session.refresh_token = Some(refresh_token);
                        }

                        // save refreshed session
                        session
                            .set(OidcSession(OidcSessionInner::Authenticated(login_session)))
                            .await
                            .map_err(|x| MiddlewareError::Session(Box::new(x)))?;
                    } else {
                        session
                            .set(OidcSession(OidcSessionInner::Unauthenticated))
                            .await
                            .map_err(|x| MiddlewareError::Session(Box::new(x)))?;
                    };
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
            if has_logout_ext {
                session
                    .set(OidcSession(OidcSessionInner::Unauthenticated))
                    .await
                    .map_err(|x| MiddlewareError::Session(Box::new(x)))?;
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
    let inner_client = client.client.load();
    let req = inner_client
        .user_info(access_token, None)
        .map_err(MiddlewareError::Configuration)?;
    req.request_async::<AC, _, CoreGenderClaim>(&client.http_client)
        .await
        .map_err(MiddlewareError::UserInfoRetrieval)
}

async fn try_refresh_token<AC: AdditionalClaims>(
    client: &OidcClient<AC>,
    refresh_token: &RefreshToken,
) -> Result<
    Option<(
        IdTokenClaims<AC, CoreGenderClaim>,
        AuthenticatedSession<AC, CoreGenderClaim>,
        Option<RefreshToken>,
    )>,
    MiddlewareError,
> {
    let inner_client = client.client.load();
    let mut refresh_request = inner_client.exchange_refresh_token(refresh_token)?;

    for scope in client.scopes.iter() {
        refresh_request = refresh_request.add_scope(Scope::new(scope.to_string()));
    }

    match refresh_request.request_async(&client.http_client).await {
        Ok(token_response) => {
            // Extract the ID token claims after verifying its authenticity and nonce.
            let id_token = token_response
                .id_token()
                .ok_or(MiddlewareError::IdTokenMissing)?;
            let id_token_verifier = inner_client
                .id_token_verifier()
                .set_other_audience_verifier_fn(|audience|
                    // Return false (reject) if audience is in list of untrusted audiences
                    !client.untrusted_audiences.contains(audience));
            // nonce validation can be ignored as the token was fetched directly from the issuer.
            let claims = id_token.claims(&id_token_verifier, |_: Option<&Nonce>| Ok(()))?;

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
        Err(ServerResponse(e))
            if *e.error() == CoreErrorResponseType::InvalidGrant
                || e.error().as_ref() == "JwtToken" =>
        {
            // Refresh failed, refresh_token most likely expired or
            // invalid, the session can be considered lost.
            // Some providers (e.g. Keycloak) return "JwtToken" instead of
            // "invalid_grant" for expired JWT-format refresh tokens.
            Ok(None)
        }
        Err(err) => Err(err.into()),
    }
}
