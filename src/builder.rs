use std::marker::PhantomData;

use http::Uri;
use openidconnect::{
    Audience, AuthenticationContextClass, ClientId, ClientSecret, IssuerUrl, Scope,
};

use crate::{error::Error, AdditionalClaims, Client, OidcClient, ProviderMetadata};

pub struct Unconfigured;
pub struct OpenidconnectClient<AC: AdditionalClaims>(crate::Client<AC>);
pub struct HttpClient(reqwest::Client);
pub struct RedirectUrl(Uri);

pub struct ClientCredentials {
    id: ClientId,
    secret: Option<ClientSecret>,
}

pub struct Builder<AC: AdditionalClaims, Credentials, Client, HttpClient, RedirectUrl> {
    credentials: Credentials,
    client: Client,
    http_client: HttpClient,
    redirect_url: RedirectUrl,
    end_session_endpoint: Option<Uri>,
    scopes: Vec<Scope>,
    auth_context_class: Option<AuthenticationContextClass>,
    untrusted_audiences: Vec<Audience>,
    _ac: PhantomData<AC>,
}

impl<AC: AdditionalClaims> Default for Builder<AC, (), (), (), ()> {
    fn default() -> Self {
        Self::new()
    }
}
impl<AC: AdditionalClaims> Builder<AC, (), (), (), ()> {
    /// create a new builder with default values
    pub fn new() -> Self {
        Self {
            credentials: (),
            client: (),
            http_client: (),
            redirect_url: (),
            end_session_endpoint: None,
            scopes: vec![Scope::new("openid".to_string())],
            auth_context_class: None,
            untrusted_audiences: Vec::new(),
            _ac: PhantomData,
        }
    }
}

impl<AC: AdditionalClaims> OidcClient<AC> {
    /// create a new builder with default values
    pub fn builder() -> Builder<AC, (), (), (), ()> {
        Builder::<AC, (), (), (), ()>::new()
    }
}

impl<AC: AdditionalClaims, CREDS, CLIENT, HTTP, RURL> Builder<AC, CREDS, CLIENT, HTTP, RURL> {
    /// add a scope to existing (default) scopes
    pub fn add_scope(mut self, scope: Scope) -> Self {
        self.scopes.push(scope);
        self
    }

    /// replace scopes (including default)
    pub fn with_scopes(mut self, scopes: Vec<Scope>) -> Self {
        self.scopes = scopes;
        self
    }

    /// authenticate with Authentication Context Class Reference
    pub fn with_auth_context_class(mut self, acr: AuthenticationContextClass) -> Self {
        self.auth_context_class = Some(acr);
        self
    }

    /// add a an untrusted audience to existing untrusted audiences
    pub fn add_untrusted_audience(mut self, audience: Audience) -> Self {
        self.untrusted_audiences.push(audience);
        self
    }

    /// replace untrusted audiences
    pub fn with_untrusted_audiences(mut self, untrusted_audiences: Vec<Audience>) -> Self {
        self.untrusted_audiences = untrusted_audiences;
        self
    }
}

impl<AC: AdditionalClaims, CLIENT, HTTP, RURL> Builder<AC, (), CLIENT, HTTP, RURL> {
    /// set client id for authentication with issuer
    pub fn with_client_id(
        self,
        id: impl Into<ClientId>,
    ) -> Builder<AC, ClientCredentials, CLIENT, HTTP, RURL> {
        Builder::<_, _, _, _, _> {
            credentials: ClientCredentials {
                id: id.into(),
                secret: None,
            },
            client: self.client,
            http_client: self.http_client,
            redirect_url: self.redirect_url,
            end_session_endpoint: self.end_session_endpoint,
            scopes: self.scopes,
            auth_context_class: self.auth_context_class,
            untrusted_audiences: self.untrusted_audiences,
            _ac: PhantomData,
        }
    }
}

impl<AC: AdditionalClaims, CLIENT, HTTP, RURL> Builder<AC, ClientCredentials, CLIENT, HTTP, RURL> {
    /// set client secret for authentication with issuer
    pub fn with_client_secret(mut self, secret: impl Into<ClientSecret>) -> Self {
        self.credentials.secret = Some(secret.into());
        self
    }
}

impl<AC: AdditionalClaims, CREDS, CLIENT, RURL> Builder<AC, CREDS, CLIENT, (), RURL> {
    /// use custom http client
    pub fn with_http_client(
        self,
        client: reqwest::Client,
    ) -> Builder<AC, CREDS, CLIENT, HttpClient, RURL> {
        Builder {
            credentials: self.credentials,
            client: self.client,
            http_client: HttpClient(client),
            redirect_url: self.redirect_url,
            end_session_endpoint: self.end_session_endpoint,
            scopes: self.scopes,
            auth_context_class: self.auth_context_class,
            untrusted_audiences: self.untrusted_audiences,
            _ac: self._ac,
        }
    }
    /// use default reqwest http client
    pub fn with_default_http_client(self) -> Builder<AC, CREDS, CLIENT, HttpClient, RURL> {
        Builder {
            credentials: self.credentials,
            client: self.client,
            http_client: HttpClient(reqwest::Client::default()),
            redirect_url: self.redirect_url,
            end_session_endpoint: self.end_session_endpoint,
            scopes: self.scopes,
            auth_context_class: self.auth_context_class,
            untrusted_audiences: self.untrusted_audiences,
            _ac: self._ac,
        }
    }
}

impl<AC: AdditionalClaims, CREDS, CLIENT, HCLIENT> Builder<AC, CREDS, CLIENT, HCLIENT, ()> {
    pub fn with_redirect_url(
        self,
        redirect_url: Uri,
    ) -> Builder<AC, CREDS, CLIENT, HCLIENT, RedirectUrl> {
        Builder {
            credentials: self.credentials,
            client: self.client,
            http_client: self.http_client,
            redirect_url: RedirectUrl(redirect_url),
            end_session_endpoint: self.end_session_endpoint,
            scopes: self.scopes,
            auth_context_class: self.auth_context_class,
            untrusted_audiences: self.untrusted_audiences,
            _ac: self._ac,
        }
    }
}

impl<AC: AdditionalClaims> Builder<AC, ClientCredentials, (), HttpClient, RedirectUrl> {
    /// provide issuer details manually
    pub fn manual(
        self,
        provider_metadata: ProviderMetadata,
    ) -> Result<
        Builder<AC, ClientCredentials, OpenidconnectClient<AC>, HttpClient, RedirectUrl>,
        Error,
    > {
        let end_session_endpoint = provider_metadata
            .additional_metadata()
            .end_session_endpoint
            .clone()
            .map(Uri::from_maybe_shared)
            .transpose()
            .map_err(Error::InvalidEndSessionEndpoint)?;
        let client = Client::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.credentials.id.to_string()),
            self.credentials.secret.clone(),
        )
        .set_redirect_uri(openidconnect::RedirectUrl::new(
            self.redirect_url.0.to_string(),
        )?);

        Ok(Builder {
            credentials: self.credentials,
            client: OpenidconnectClient(client),
            http_client: self.http_client,
            redirect_url: self.redirect_url,
            end_session_endpoint,
            scopes: self.scopes,
            auth_context_class: self.auth_context_class,
            untrusted_audiences: self.untrusted_audiences,
            _ac: self._ac,
        })
    }
    /// discover issuer details
    pub async fn discover(
        self,
        issuer: IssuerUrl,
    ) -> Result<
        Builder<AC, ClientCredentials, OpenidconnectClient<AC>, HttpClient, RedirectUrl>,
        Error,
    > {
        let http_client = self.http_client.0.clone();
        let provider_metadata = ProviderMetadata::discover_async(issuer, &http_client);

        Self::manual(self, provider_metadata.await?)
    }
}

impl<AC: AdditionalClaims>
    Builder<AC, ClientCredentials, OpenidconnectClient<AC>, HttpClient, RedirectUrl>
{
    /// create oidc client
    pub fn build(self) -> OidcClient<AC> {
        OidcClient {
            scopes: self.scopes,
            client_id: self.credentials.id,
            client: self.client.0,
            http_client: self.http_client.0,
            end_session_endpoint: self.end_session_endpoint,
            auth_context_class: self.auth_context_class,
            untrusted_audiences: self.untrusted_audiences,
        }
    }
}
