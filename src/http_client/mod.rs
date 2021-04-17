use std::sync::Arc;

use url::Url;

use super::error::Result;

mod client_impl;
#[cfg(feature = "networking")]
mod reqwest_client;

pub use client_impl::{ClientImplementation, Response};

#[cfg(feature = "networking")]
use reqwest_client::Client as ReqwestImpl;

/// The network client to use to interact with the Etebase server
///
/// This is in charge of actually connecting to the server and making network requests. Depending
/// on your configuration this can be overridden and replaced with a completely different
/// implementation.
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
        if !ret.path().ends_with("/") {
            ret.path_segments_mut().unwrap().push("");
        }
        Ok(ret)
    }

    /// Return a new client object
    ///
    /// The client object manages the connection to the Etebase server
    ///
    /// # Arguments:
    /// * `client_name` - a string identifier for the client
    /// * `server_url` - the Etebase server URL
    #[cfg(feature = "networking")]
    pub fn new(client_name: &str, server_url: &str) -> Result<Self> {
        let imp = ReqwestImpl::new(client_name)?;
        Ok(Self {
            api_base: Self::normalize_url(server_url)?,
            auth_token: None,
            imp: Arc::new(imp),
        })
    }

    #[cfg(not(feature = "networking"))]
    pub fn new_with_impl(server_url: &str, imp: Box<dyn ClientImplementation>) -> Result<Self> {
        Ok(Self {
            api_base: Self::normalize_url(server_url)?,
            auth_token: None,
            imp: Arc::new(imp),
        })
    }

    pub(crate) fn set_token(&mut self, token: Option<&str>) {
        self.auth_token = token.map(str::to_string)
    }

    pub(crate) fn token(&self) -> Option<&str> {
        self.auth_token.as_deref()
    }

    /// Set the server url associated with this client
    pub fn set_server_url(&mut self, server_url: &str) -> Result<()> {
        self.api_base = Self::normalize_url(server_url)?;

        Ok(())
    }

    /// Return the server url associated with this client
    pub fn server_url(&self) -> &Url {
        &self.api_base
    }

    pub(crate) fn get(&self, url: &str) -> Result<Response> {
        self.imp.get(url, self.auth_token.as_deref()).as_result()
    }

    pub(crate) fn post(&self, url: &str, body: Vec<u8>) -> Result<Response> {
        self.imp
            .post(url, self.auth_token.as_deref(), body)
            .as_result()
    }

    pub(crate) fn put(&self, url: &str, body: Vec<u8>) -> Result<Response> {
        self.imp
            .put(url, self.auth_token.as_deref(), body)
            .as_result()
    }

    pub(crate) fn patch(&self, url: &str, body: Vec<u8>) -> Result<Response> {
        self.imp
            .patch(url, self.auth_token.as_deref(), body)
            .as_result()
    }

    pub(crate) fn delete(&self, url: &str) -> Result<Response> {
        self.imp.delete(url, self.auth_token.as_deref()).as_result()
    }
}
