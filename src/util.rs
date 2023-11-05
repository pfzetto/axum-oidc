use http::{uri::PathAndQuery, Uri};

use crate::error::MiddlewareError;

/// Helper function to remove the OpenID Connect authentication response query attributes from a
/// [`Uri`].
pub fn strip_oidc_from_path(base_url: Uri, uri: &Uri) -> Result<Uri, MiddlewareError> {
    let mut base_url = base_url.into_parts();

    base_url.path_and_query = uri
        .path_and_query()
        .map(|path_and_query| {
            let query = path_and_query
                .query()
                .and_then(|uri| {
                    uri.split('&')
                        .filter(|x| {
                            !x.starts_with("code")
                                && !x.starts_with("state")
                                && !x.starts_with("session_state")
                        })
                        .map(|x| x.to_string())
                        .reduce(|acc, x| acc + "&" + &x)
                })
                .map(|x| "?" + x)
                .unwrap_or_default();

            PathAndQuery::from_maybe_shared(format!("{}{}", path_and_query.path(), query))
        })
        .transpose()?;

    Ok(Uri::from_parts(base_url)?)
}
