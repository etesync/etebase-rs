mod java_glue;
pub use crate::java_glue::*;

use std::rc::Rc;
use std::cell::RefCell;

use etebase::{
    Client,
    http_custom_client::{
        ClientImplementation,
        Response as EtebaseResponse,
    },

    error::{
        Error,
        Result,
    },
};

pub struct Response {
    inner: Rc<RefCell<EtebaseResponse>>,
}

impl Response {
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(EtebaseResponse::new_err(Error::ProgrammingError("Got a generic response error")))),
        }
    }

    pub fn reset_ok(&mut self, bytes: Vec<u8>, status: u16) {
        self.inner.borrow_mut().reset_ok(bytes, status)
    }

    pub fn reset_err(&mut self, err: String) {
        self.inner.borrow_mut().reset_err(Error::Connection(err))
    }

    pub fn inner_copy(&self) -> Rc<RefCell<EtebaseResponse>> {
        Rc::clone(&self.inner)
    }
}

pub trait HttpClient {
    fn get(&self, url: &str, auth_token: &str, response: Response);
    fn post(&self, url: &str, auth_token: &str, body: Vec<u8>, response: Response);
    fn put(&self, url: &str, auth_token: &str, body: Vec<u8>, response: Response);
    fn patch(&self, url: &str, auth_token: &str, body: Vec<u8>, response: Response);
    fn delete(&self, url: &str, auth_token: &str, response: Response);
}

struct JavaHttpClient {
    imp: Box<dyn HttpClient>,
}

impl JavaHttpClient {
    pub fn new(imp: Box<dyn HttpClient>) -> Self {
        Self {
            imp,
        }
    }
}

impl ClientImplementation for JavaHttpClient {
    fn get(&self, url: &str, auth_token: Option<&str>) -> EtebaseResponse {
        let response = Response::new();
        let inner = response.inner_copy();
        self.imp.get(url, auth_token.unwrap_or(""), response);
        let inner = inner.borrow();
        inner.clone()
    }

    fn post(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> EtebaseResponse {
        let response = Response::new();
        let inner = response.inner_copy();
        self.imp.post(url, auth_token.unwrap_or(""), body, response);
        let inner = inner.borrow();
        inner.clone()
    }
    fn put(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> EtebaseResponse {
        let response = Response::new();
        let inner = response.inner_copy();
        self.imp.put(url, auth_token.unwrap_or(""), body, response);
        let inner = inner.borrow();
        inner.clone()
    }
    fn patch(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> EtebaseResponse {
        let response = Response::new();
        let inner = response.inner_copy();
        self.imp.patch(url, auth_token.unwrap_or(""), body, response);
        let inner = inner.borrow();
        inner.clone()
    }
    fn delete(&self, url: &str, auth_token: Option<&str>) -> EtebaseResponse {
        let response = Response::new();
        let inner = response.inner_copy();
        self.imp.delete(url, auth_token.unwrap_or(""), response);
        let inner = inner.borrow();
        inner.clone()
    }
}

pub fn client_new_with_impl(server_url: &str, imp: Box<dyn HttpClient>) -> Result<Client> {
    let imp = Box::new(JavaHttpClient::new(imp));
    Client::new_with_impl(server_url, imp)
}

pub struct FetchOptions {
    limit: Option<usize>,
    stoken: Option<String>,
    iterator: Option<String>,
    prefetch: Option<bool>,
    with_collection: Option<bool>,
}

impl FetchOptions {
    pub fn new() -> Self {
        Self {
            limit: None,
            stoken: None,
            iterator: None,
            prefetch: None,
            with_collection: None,
        }
    }

    pub fn limit(&mut self, limit: usize) {
        self.limit = Some(limit);
    }

    pub fn prefetch(&mut self, prefetch: bool) {
        self.prefetch = Some(prefetch);
    }

    pub fn with_collection(&mut self, with_collection: bool) {
        self.with_collection = Some(with_collection);
    }

    pub fn iterator(&mut self, iterator: Option<&str>) {
        self.iterator = iterator.map(str::to_string);
    }

    pub fn stoken(&mut self, stoken: Option<&str>) {
        self.stoken = stoken.map(str::to_string);
    }

    pub fn to_fetch_options<'a>(&'a self) -> etebase::FetchOptions<'a> {
        let mut ret = etebase::FetchOptions::new();
        if let Some(limit) = self.limit {
            ret = ret.limit(limit);
        }
        if let Some(prefetch) = self.prefetch {
            ret = ret.prefetch(prefetch);
        }
        if let Some(with_collection) = self.with_collection {
            ret = ret.with_collection(with_collection);
        }
        ret = ret.iterator(self.iterator.as_deref());
        ret = ret.stoken(self.stoken.as_deref());
        ret
    }
}
