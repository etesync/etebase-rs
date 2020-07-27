use std::rc::Rc;

use url::Url;

use super::error::Result;

mod client_impl;
#[cfg(feature = "networking")]
mod reqwest_client;
#[cfg(not(feature = "networking"))]
mod noop_client;

pub use client_impl::{
    ClientImplementation,
    Response,
};

#[cfg(feature = "networking")]
use reqwest_client::Client as ReqwestImpl;
#[cfg(not(feature = "networking"))]
use noop_client::Client as NoopImpl;

#[derive(Clone)]
pub struct Client {
    auth_token: Option<String>,
    pub(crate) api_base: Url,
    imp: Rc<Box<dyn ClientImplementation>>,
}

impl Client {
    #[cfg(feature = "networking")]
    pub fn new(client_name: &str, server_url: &str) -> Result<Self> {
        let imp = Box::new(ReqwestImpl::new(client_name)?);
        Self::new_with_impl(server_url, imp)
    }

    #[cfg(not(feature = "networking"))]
    pub fn new(client_name: &str, server_url: &str) -> Result<Self> {
        let imp = Box::new(NoopImpl::new(client_name)?);
        Self::new_with_impl(server_url, imp)
    }

    pub fn new_with_impl(server_url: &str, imp: Box<dyn ClientImplementation>) -> Result<Self> {
        Ok(Self {
            api_base: Url::parse(server_url)?,
            auth_token: None,
            imp: Rc::new(imp),
        })
    }

    pub fn set_token(&mut self, token: Option<&str>) {
        self.auth_token = token.map(str::to_string)
    }

    pub fn token(&self) -> Option<&str> {
        self.auth_token.as_deref()
    }

    pub fn set_api_base(&mut self, server_url: &str) -> Result<()> {
        self.api_base = Url::parse(server_url)?;

        Ok(())
    }

    pub fn api_base(&self) -> &Url {
        &self.api_base
    }

    pub fn get(&self, url: &str) -> Result<Response> {
        self.imp.get(url, self.auth_token.as_deref()).as_result()
    }

    pub fn post(&self, url: &str, body: Vec<u8>) -> Result<Response> {
        self.imp.post(url, self.auth_token.as_deref(), body).as_result()
    }

    pub fn put(&self, url: &str, body: Vec<u8>) -> Result<Response> {
        self.imp.put(url, self.auth_token.as_deref(), body).as_result()
    }

    pub fn patch(&self, url: &str, body: Vec<u8>) -> Result<Response> {
        self.imp.patch(url, self.auth_token.as_deref(), body).as_result()
    }

    pub fn delete(&self, url: &str) -> Result<Response> {
        self.imp.delete(url, self.auth_token.as_deref()).as_result()
    }
}
