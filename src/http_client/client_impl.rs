use serde::Deserialize;

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

#[derive(Clone)]
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

    pub fn reset_ok(&mut self, bytes: Vec<u8>, status: u16) {
        self.bytes = bytes;
        self.status = status;
        self.err = None;
    }

    pub fn reset_err(&mut self, err: Error) {
        self.err = Some(err);
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

        #[derive(Deserialize)]
        struct ErrorResponse<'a> {
            pub code: Option<&'a str>,
            pub detail: Option<&'a str>,
        }

        let content: ErrorResponse = rmp_serde::from_read_ref(self.bytes())
            .unwrap_or(ErrorResponse { code: None, detail: None });

        Err(match self.status {
            // FIXME: Use the detail too
            401 => Error::Unauthorized(content.detail.unwrap_or("Unauthorized").to_string()),
            403 => Error::PermissionDenied(content.detail.unwrap_or("PermissionDenied").to_string()),
            409 => Error::Conflict(content.detail.unwrap_or("Conflict").to_string()),
            status => Error::Http(format!("HTTP error {}! Code: '{}'. Detail: '{}'", status, content.code.unwrap_or("null"), content.detail.unwrap_or("null"))),
        })
    }

    pub fn as_result(self) -> Result<Self> {
        match self.err {
            Some(err) => Err(err),
            None => Ok(self),
        }
    }
}
