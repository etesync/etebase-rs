use crate::error::{
    Result,
    Error,
};

use super::client_impl::{
    ClientImplementation,
    Response,
};

pub struct Client {
}

impl Client {
    pub fn new(_client_name: &str) -> Result<Self> {
        Ok(Self {
        })
    }
}

impl ClientImplementation for Client {
    fn get(&self, _url: &str, _auth_token: Option<&str>) -> Response {
        Response::new_err(Error::ProgrammingError("Tried using the noop networking backend."))
    }

    fn post(&self, _url: &str, _auth_token: Option<&str>, _body: Vec<u8>) -> Response {
        Response::new_err(Error::ProgrammingError("Tried using the noop networking backend."))
    }

    fn put(&self, _url: &str, _auth_token: Option<&str>, _body: Vec<u8>) -> Response {
        Response::new_err(Error::ProgrammingError("Tried using the noop networking backend."))
    }

    fn patch(&self, _url: &str, _auth_token: Option<&str>, _body: Vec<u8>) -> Response {
        Response::new_err(Error::ProgrammingError("Tried using the noop networking backend."))
    }

    fn delete(&self, _url: &str, _auth_token: Option<&str>) -> Response {
        Response::new_err(Error::ProgrammingError("Tried using the noop networking backend."))
    }
}
