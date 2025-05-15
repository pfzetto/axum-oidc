use axum::{
    extract::{Query, State},
    response::Redirect,
    Extension,
};
use openidconnect::{
    core::{CoreGenderClaim, CoreJsonWebKey},
    AccessToken, AccessTokenHash, AuthorizationCode, IdTokenClaims, IdTokenVerifier,
    OAuth2TokenResponse, PkceCodeVerifier, TokenResponse,
};
use serde::Deserialize;
use tower_sessions::Session;

use crate::{
    error::HandlerError, AdditionalClaims, AuthenticatedSession, Config, IdToken, OidcClient,
    OidcSession, SESSION_KEY,
};

/// response data of the openid issuer after login
#[derive(Debug, Deserialize)]
pub struct OidcQuery {
    code: String,
    state: String,
    #[allow(dead_code)]
    session_state: Option<String>,
}

#[tracing::instrument(skip(oidcclient), err)]
pub async fn handle_oidc_redirect<AC: AdditionalClaims>(
    session: Session,
    Extension(oidcclient): Extension<OidcClient<AC>>,
    State(config): State<Config>,
    Query(query): Query<OidcQuery>,
) -> Result<impl axum::response::IntoResponse, HandlerError> {
    
    tracing::debug!("start handling oidc redirect");

    let mut login_session: OidcSession<AC> = session
        .get(SESSION_KEY)
        .await?
        .ok_or(HandlerError::RedirectedWithoutSession)?;
    // the request has the request headers of the oidc redirect
    // parse the headers and exchange the code for a valid token

    tracing::debug!("validating scrf token");
    if login_session.csrf_token.secret() != &query.state {
        return Err(HandlerError::CsrfTokenInvalid);
    }

    tracing::debug!("obtain token response");
    let token_response = oidcclient
        .client
        .exchange_code(AuthorizationCode::new(query.code.to_string()))?
        // Set the PKCE code verifier.
        .set_pkce_verifier(PkceCodeVerifier::new(
            login_session.pkce_verifier.secret().to_string(),
        ))
        .request_async(&oidcclient.http_client)
        .await?;

    tracing::debug!("extract claims and verify it");
    // Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response
        .id_token()
        .ok_or(HandlerError::IdTokenMissing)?;
    let id_token_verifier = oidcclient
        .client
        .id_token_verifier()
        .set_other_audience_verifier_fn(|audience| config.other_audiences.contains(audience));
    let claims = id_token.claims(&id_token_verifier, &login_session.nonce)?;

    tracing::debug!("validate access token hash");
    validate_access_token_hash(
        id_token,
        id_token_verifier,
        token_response.access_token(),
        claims,
    )
    .inspect_err(|e| tracing::error!(?e, "Access token hash invalid"))?;

    tracing::debug!("Access token hash validated");

    login_session.authenticated = Some(AuthenticatedSession {
        id_token: id_token.clone(),
        access_token: token_response.access_token().clone(),
    });
    let refresh_token = token_response.refresh_token().cloned();
    if let Some(refresh_token) = refresh_token {
        login_session.refresh_token = Some(refresh_token);
    }

    tracing::debug!(
        "Inserting session and redirecting to {}",
        &login_session.redirect_url
    );
    let redirect_url = login_session.redirect_url.clone();
    session.insert(SESSION_KEY, login_session).await?;

    Ok(Redirect::to(&redirect_url))
}

/// Verify the access token hash to ensure that the access token hasn't been substituted for
/// another user's.
/// Returns `Ok` when access token is valid
#[tracing::instrument(skip_all, err)]
fn validate_access_token_hash<AC: AdditionalClaims>(
    id_token: &IdToken<AC>,
    id_token_verifier: IdTokenVerifier<CoreJsonWebKey>,
    access_token: &AccessToken,
    claims: &IdTokenClaims<AC, CoreGenderClaim>,
) -> Result<(), HandlerError> {
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            access_token,
            id_token.signing_alg()?,
            id_token.signing_key(&id_token_verifier)?,
        )?;
        if actual_access_token_hash == *expected_access_token_hash {
            Ok(())
        } else {
            Err(HandlerError::AccessTokenHashInvalid)
        }
    } else {
        Ok(())
    }
}
