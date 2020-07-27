use std::rc::Rc;

use url::Url;

use super::error::Result;

mod client_impl;
mod reqwest_client;

pub use client_impl::{
    ClientImplementation,
    Response,
};
use reqwest_client::Client as ReqwestImpl;

#[derive(Clone)]
pub struct Client {
    auth_token: Option<String>,
    pub(crate) api_base: Url,
    imp: Rc<Box<dyn ClientImplementation>>,
}

impl Client {
    pub fn new(client_name: &str, server_url: &str) -> Result<Self> {
        Ok(Self{
            api_base: Url::parse(server_url)?,
            auth_token: None,
            imp: Rc::new(Box::new(ReqwestImpl::new(client_name)?)),
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
