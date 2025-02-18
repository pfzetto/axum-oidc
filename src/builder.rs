use std::marker::PhantomData;

use http::Uri;
use openidconnect::{ClientId, ClientSecret, IssuerUrl};

use crate::{error::Error, AdditionalClaims, Client, OidcClient, ProviderMetadata};

pub struct Unconfigured;
pub struct ApplicationBaseUrl(Uri);
pub struct OpenidconnectClient<AC: AdditionalClaims>(crate::Client<AC>);
pub struct HttpClient(reqwest::Client);

pub struct ClientCredentials {
    id: Box<str>,
    secret: Option<Box<str>>,
}

pub struct Builder<AC: AdditionalClaims, ApplicationBaseUrl, Credentials, Client, HttpClient> {
    application_base_url: ApplicationBaseUrl,
    credentials: Credentials,
    client: Client,
    http_client: HttpClient,
    end_session_endpoint: Option<Uri>,
    scopes: Vec<Box<str>>,
    oidc_request_parameters: Vec<Box<str>>,
    auth_context_class: Option<Box<str>>,
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
        let oidc_request_parameters = ["code", "state", "session_state", "iss"]
            .into_iter()
            .map(Box::<str>::from)
            .collect();

        Self {
            application_base_url: (),
            credentials: (),
            client: (),
            http_client: (),
            end_session_endpoint: None,
            scopes: vec![Box::from("openid")],
            oidc_request_parameters,
            auth_context_class: None,
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

impl<AC: AdditionalClaims, APPBASE, CREDS, CLIENT, HTTP> Builder<AC, APPBASE, CREDS, CLIENT, HTTP> {
    /// add a scope to existing (default) scopes
    pub fn add_scope(mut self, scope: impl Into<Box<str>>) -> Self {
        self.scopes.push(scope.into());
        self
    }
    /// replace scopes (including default)
    pub fn with_scopes(mut self, scopes: impl Iterator<Item = impl Into<Box<str>>>) -> Self {
        self.scopes = scopes.map(|x| x.into()).collect::<Vec<_>>();
        self
    }

    /// add a query parameter that will be filtered from requests to existing (default) filtered
    /// query parameters
    pub fn add_oidc_request_parameter(
        mut self,
        oidc_request_parameter: impl Into<Box<str>>,
    ) -> Self {
        self.oidc_request_parameters
            .push(oidc_request_parameter.into());
        self
    }

    /// replace query parameters that will be filtered from requests (including default)
    pub fn with_oidc_request_parameters(
        mut self,
        oidc_request_parameters: impl Iterator<Item = impl Into<Box<str>>>,
    ) -> Self {
        self.oidc_request_parameters = oidc_request_parameters
            .map(|x| x.into())
            .collect::<Vec<_>>();
        self
    }

    /// authenticate with Authentication Context Class Reference
    pub fn with_auth_context_class(mut self, acr: impl Into<Box<str>>) -> Self {
        self.auth_context_class = Some(acr.into());
        self
    }
}

impl<AC: AdditionalClaims, CREDS, CLIENT, HTTP> Builder<AC, (), CREDS, CLIENT, HTTP> {
    /// set application base url (e.g. https://example.com)
    pub fn with_application_base_url(
        self,
        url: impl Into<Uri>,
    ) -> Builder<AC, ApplicationBaseUrl, CREDS, CLIENT, HTTP> {
        Builder {
            application_base_url: ApplicationBaseUrl(url.into()),
            credentials: self.credentials,
            client: self.client,
            http_client: self.http_client,
            end_session_endpoint: self.end_session_endpoint,
            scopes: self.scopes,
            oidc_request_parameters: self.oidc_request_parameters,
            auth_context_class: self.auth_context_class,
            _ac: PhantomData,
        }
    }
}

impl<AC: AdditionalClaims, ABU, CLIENT, HTTP> Builder<AC, ABU, (), CLIENT, HTTP> {
    /// set client id for authentication with issuer
    pub fn with_client_id(
        self,
        id: impl Into<Box<str>>,
    ) -> Builder<AC, ABU, ClientCredentials, CLIENT, HTTP> {
        Builder::<_, _, _, _, _> {
            application_base_url: self.application_base_url,
            credentials: ClientCredentials {
                id: id.into(),
                secret: None,
            },
            client: self.client,
            http_client: self.http_client,
            end_session_endpoint: self.end_session_endpoint,
            scopes: self.scopes,
            oidc_request_parameters: self.oidc_request_parameters,
            auth_context_class: self.auth_context_class,
            _ac: PhantomData,
        }
    }
}

impl<AC: AdditionalClaims, ABU, CLIENT, HTTP> Builder<AC, ABU, ClientCredentials, CLIENT, HTTP> {
    /// set client secret for authentication with issuer
    pub fn with_client_secret(mut self, secret: impl Into<Box<str>>) -> Self {
        self.credentials.secret = Some(secret.into());
        self
    }
}

impl<AC: AdditionalClaims, ABU, CREDS, CLIENT> Builder<AC, ABU, CREDS, CLIENT, ()> {
    /// use custom http client
    pub fn with_http_client(
        self,
        client: reqwest::Client,
    ) -> Builder<AC, ABU, CREDS, CLIENT, HttpClient> {
        Builder {
            application_base_url: self.application_base_url,
            credentials: self.credentials,
            client: self.client,
            http_client: HttpClient(client),
            end_session_endpoint: self.end_session_endpoint,
            scopes: self.scopes,
            oidc_request_parameters: self.oidc_request_parameters,
            auth_context_class: self.auth_context_class,
            _ac: self._ac,
        }
    }
    /// use default reqwest http client
    pub fn with_default_http_client(self) -> Builder<AC, ABU, CREDS, CLIENT, HttpClient> {
        Builder {
            application_base_url: self.application_base_url,
            credentials: self.credentials,
            client: self.client,
            http_client: HttpClient(reqwest::Client::default()),
            end_session_endpoint: self.end_session_endpoint,
            scopes: self.scopes,
            oidc_request_parameters: self.oidc_request_parameters,
            auth_context_class: self.auth_context_class,
            _ac: self._ac,
        }
    }
}

impl<AC: AdditionalClaims, ABU> Builder<AC, ABU, ClientCredentials, (), HttpClient> {
    /// provide issuer details manually
    pub fn manual(
        self,
        provider_metadata: ProviderMetadata,
    ) -> Result<Builder<AC, ABU, ClientCredentials, OpenidconnectClient<AC>, HttpClient>, Error>
    {
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
            self.credentials
                .secret
                .as_ref()
                .map(|x| ClientSecret::new(x.to_string())),
        );

        Ok(Builder {
            application_base_url: self.application_base_url,
            credentials: self.credentials,
            client: OpenidconnectClient(client),
            http_client: self.http_client,
            end_session_endpoint,
            scopes: self.scopes,
            oidc_request_parameters: self.oidc_request_parameters,
            auth_context_class: self.auth_context_class,
            _ac: self._ac,
        })
    }
    /// discover issuer details
    pub async fn discover(
        self,
        issuer: impl Into<Uri>,
    ) -> Result<Builder<AC, ABU, ClientCredentials, OpenidconnectClient<AC>, HttpClient>, Error>
    {
        let issuer_url = IssuerUrl::new(issuer.into().to_string())?;
        let http_client = self.http_client.0.clone();
        let provider_metadata = ProviderMetadata::discover_async(issuer_url, &http_client);

        Self::manual(self, provider_metadata.await?)
    }
}

impl<AC: AdditionalClaims>
    Builder<AC, ApplicationBaseUrl, ClientCredentials, OpenidconnectClient<AC>, HttpClient>
{
    /// create oidc client
    pub fn build(self) -> OidcClient<AC> {
        OidcClient {
            scopes: self.scopes,
            oidc_request_parameters: self.oidc_request_parameters,
            client_id: self.credentials.id,
            client: self.client.0,
            http_client: self.http_client.0,
            application_base_url: self.application_base_url.0,
            end_session_endpoint: self.end_session_endpoint,
            auth_context_class: self.auth_context_class,
        }
    }
}
