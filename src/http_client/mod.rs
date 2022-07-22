use std::sync::Arc;

use url::Url;

use crate::{error::Error, online_managers::Authenticator};

use super::error::Result;

mod client_impl;
#[cfg(feature = "networking")]
mod reqwest_client;

pub use client_impl::{ClientImplementation, Response};

#[cfg(feature = "networking")]
use reqwest_client::Client as ReqwestImpl;

/// The network client to use to interact with the Etebase server
///
/// This is in charge of actually connecting to the server and making network requests.
/// If the `"networking"` crate feature is enabled, it uses an internal HTTP client based on
/// the `reqwest` crate. If the feature is not enabled, an external HTTP(S) client implementation
/// implementing the [`ClientImplementation`] trait needs to be supplied.
#[derive(Clone)]
pub struct Client {
    auth_token: Option<String>,
    pub(crate) api_base: Url,
    #[cfg(feature = "networking")]
    imp: Arc<ReqwestImpl>,
    #[cfg(not(feature = "networking"))]
    imp: Arc<Box<dyn ClientImplementation>>,
}

impl Client {
    fn normalize_url(server_url: &str) -> Result<Url> {
        let mut ret = Url::parse(server_url)?;

        if !["http", "https"].contains(&ret.scheme()) {
            return Err(Error::UrlParse(format!(
                "Invalid server URL scheme, expected http or https: {}",
                ret.scheme()
            )));
        }

        if !ret.path().ends_with('/') {
            ret.path_segments_mut().unwrap().push("");
        }
        Ok(ret)
    }

    /// Creates a new client object for the server located at `server_url`.
    ///
    /// The `client_name` will be used to populate the `User-Agent` header in all requests
    /// to the server.
    ///
    /// # Examples
    ///
    /// ```
    /// use etebase::Client;
    ///
    /// // For an application called "FancyClient"
    /// let my_client = Client::new("FancyClient", "https://myhost.example");
    /// ```
    #[cfg(feature = "networking")]
    pub fn new(client_name: &str, server_url: &str) -> Result<Self> {
        let imp = ReqwestImpl::new(client_name)?;
        Ok(Self {
            api_base: Self::normalize_url(server_url)?,
            auth_token: None,
            imp: Arc::new(imp),
        })
    }

    /// Creates a new client object for the server located at `server_url` using a user-supplied
    /// HTTP(S) client implementation.
    ///
    /// # Examples
    ///
    /// ```
    /// use etebase::{Client, http_custom_client::ClientImplementation};
    /// # use etebase::http_custom_client::Response;
    /// # struct ExternalClient;
    ///
    /// // For some `ExternalClient` provided by the HTTP client implementation of choice:
    /// impl ClientImplementation for ExternalClient {
    ///     // ...
    /// #   fn get(&self, _: &str, _: Option<&str>) -> Response { unimplemented!() }
    /// #   fn post(&self, _: &str, _: Option<&str>, _: Vec<u8>) -> Response { unimplemented!() }
    /// #   fn put(&self, _: &str, _: Option<&str>, _: Vec<u8>) -> Response { unimplemented!() }
    /// #   fn patch(&self, _: &str, _: Option<&str>, _: Vec<u8>) -> Response { unimplemented!() }
    /// #   fn delete(&self, _: &str, _: Option<&str>) -> Response { unimplemented!() }
    /// }
    ///
    /// let external_client = Box::new(ExternalClient);
    /// let my_client = Client::new_with_impl("https://myhost.example", external_client);
    /// ```
    #[cfg(not(feature = "networking"))]
    pub fn new_with_impl(server_url: &str, imp: Box<dyn ClientImplementation>) -> Result<Self> {
        Ok(Self {
            api_base: Self::normalize_url(server_url)?,
            auth_token: None,
            imp: Arc::new(imp),
        })
    }

    /// Checks whether the [`Client`] is pointing to a valid Etebase server.
    ///
    /// # Examples
    ///
    /// ```
    /// use etebase::Client;
    ///
    /// let invalid_client = Client::new("ExampleClient", "https://example.com").unwrap();
    /// assert!(!invalid_client.is_server_valid().unwrap());
    ///
    /// let valid_client = Client::new("ExampleClient", "https://api.etebase.com/").unwrap();
    /// assert!(valid_client.is_server_valid().unwrap());
    /// ```
    pub fn is_server_valid(&self) -> Result<bool> {
        Authenticator::new(self).is_etebase_server()
    }

    pub(crate) fn set_token(&mut self, token: Option<&str>) {
        self.auth_token = token.map(str::to_string)
    }

    pub(crate) fn token(&self) -> Option<&str> {
        self.auth_token.as_deref()
    }

    /// Set the server url associated with this client
    ///
    /// # Examples
    ///
    /// ```
    /// use etebase::Client;
    ///
    /// let mut client = Client::new("ExampleClient", "https://invalid.example").unwrap();
    /// client.set_server_url("https://another.example");
    ///
    /// assert_eq!(client.server_url().to_string(), "https://another.example/");
    /// ```
    pub fn set_server_url(&mut self, server_url: &str) -> Result<()> {
        self.api_base = Self::normalize_url(server_url)?;

        Ok(())
    }

    /// Return the server url associated with this client
    ///
    /// # Examples
    ///
    /// ```
    /// use etebase::Client;
    ///
    /// let client = Client::new("ExampleClient", "https://invalid.example").unwrap();
    ///
    /// assert_eq!(client.server_url().to_string(), "https://invalid.example/");
    /// ```
    pub fn server_url(&self) -> &Url {
        &self.api_base
    }

    pub(crate) fn get(&self, url: &str) -> Result<Response> {
        self.imp.get(url, self.auth_token.as_deref()).into_result()
    }

    pub(crate) fn post(&self, url: &str, body: Vec<u8>) -> Result<Response> {
        self.imp
            .post(url, self.auth_token.as_deref(), body)
            .into_result()
    }

    pub(crate) fn put(&self, url: &str, body: Vec<u8>) -> Result<Response> {
        self.imp
            .put(url, self.auth_token.as_deref(), body)
            .into_result()
    }

    pub(crate) fn patch(&self, url: &str, body: Vec<u8>) -> Result<Response> {
        self.imp
            .patch(url, self.auth_token.as_deref(), body)
            .into_result()
    }

    pub(crate) fn delete(&self, url: &str) -> Result<Response> {
        self.imp
            .delete(url, self.auth_token.as_deref())
            .into_result()
    }
}
