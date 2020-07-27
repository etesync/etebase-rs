use crate::error::{
    Error,
    Result,
};

pub trait ClientImplementation {
    fn get(&self, url: &str, auth_token: Option<&str>) -> Response;
    fn post(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> Response;
    fn put(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> Response;
    fn patch(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> Response;
    fn delete(&self, url: &str, auth_token: Option<&str>) -> Response;
}

pub struct Response {
    bytes: Vec<u8>,
    status: u16,
    err: Option<Error>,
}

impl Response {
    pub fn new(bytes: Vec<u8>, status: u16) -> Self {
        Self {
            bytes,
            status,
            err: None,
        }
    }

    pub fn new_err(err: Error) -> Self {
        Self {
            bytes: vec![],
            status: 0,
            err: Some(err),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn error_for_status(&self) -> Result<()> {
        if self.status >= 200 && self.status <300 {
            return Ok(())
        }
        Err(match self.status {
            401 => Error::Unauthorized("Unauthorized".to_string()),
            409 => Error::Conflict("Conflict".to_string()),
            status => Error::Http(format!("HTTP error. Status: {}", status)),
        })
    }

    pub fn as_result(self) -> Result<Self> {
        match self.err {
            Some(err) => Err(err),
            None => Ok(self),
        }
    }
}
