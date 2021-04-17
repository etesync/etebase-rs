use serde::Deserialize;

use crate::error::{Error, Result};

/// A trait for implementing a custom [network client](crate::Client)
pub trait ClientImplementation {
    /// Makes a GET request
    fn get(&self, url: &str, auth_token: Option<&str>) -> Response;
    /// Makes a POST request
    fn post(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> Response;
    /// Makes a PUT request
    fn put(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> Response;
    /// Makes a PATCH request
    fn patch(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> Response;
    /// Makes a DELETE request
    fn delete(&self, url: &str, auth_token: Option<&str>) -> Response;
}

/// An network response as returned from [network clients](ClientImplementation)
#[derive(Clone)]
pub struct Response {
    bytes: Vec<u8>,
    status: u16,
    err: Option<Error>,
}

impl Response {
    /// Creates a new valid response object
    ///
    /// # Arguments:
    /// * `bytes` - the raw resposne body
    /// * `status` - the response status code
    pub fn new(bytes: Vec<u8>, status: u16) -> Self {
        Self {
            bytes,
            status,
            err: None,
        }
    }

    /// Creates a new error response object
    ///
    /// # Arguments:
    /// * `err` - the associated [Error]
    pub fn new_err(err: Error) -> Self {
        Self {
            bytes: vec![],
            status: 0,
            err: Some(err),
        }
    }

    /// Reset the response object to a valid state as if it was created with [Self::new]
    ///
    /// # Arguments:
    /// * `bytes` - the raw resposne body
    /// * `status` - the response status code
    pub fn reset_ok(&mut self, bytes: Vec<u8>, status: u16) {
        self.bytes = bytes;
        self.status = status;
        self.err = None;
    }

    /// Reset the response object to an state as if it was created with [Self::new_err]
    ///
    /// # Arguments:
    /// * `err` - the associated [Error]
    pub fn reset_err(&mut self, err: Error) {
        self.err = Some(err);
    }

    /// Get the response body as bytes
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the response status code
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Returns [Ok] for valid responses and an [Error] object on error
    pub fn error_for_status(&self) -> Result<()> {
        if self.status >= 200 && self.status < 300 {
            return Ok(());
        }

        #[derive(Deserialize)]
        struct ErrorResponse<'a> {
            pub code: Option<&'a str>,
            pub detail: Option<&'a str>,
        }

        let content: ErrorResponse =
            rmp_serde::from_read_ref(self.bytes()).unwrap_or(ErrorResponse {
                code: None,
                detail: None,
            });

        Err(match self.status {
            // FIXME: Use the detail too
            300..=399 => Error::NotFound("Got a redirect - should never happen".to_string()),
            401 => Error::Unauthorized(content.detail.unwrap_or("Unauthorized").to_string()),
            403 => {
                Error::PermissionDenied(content.detail.unwrap_or("PermissionDenied").to_string())
            }
            404 => Error::NotFound(content.detail.unwrap_or("NotFound").to_string()),
            409 => Error::Conflict(content.detail.unwrap_or("Conflict").to_string()),
            502..=504 => Error::TemporaryServerError(
                content
                    .detail
                    .unwrap_or("Temporary server error")
                    .to_string(),
            ),
            500..=501 | 505..=599 => {
                Error::ServerError(content.detail.unwrap_or("Server error").to_string())
            }
            status => Error::Http(format!(
                "HTTP error {}! Code: '{}'. Detail: '{}'",
                status,
                content.code.unwrap_or("null"),
                content.detail.unwrap_or("null")
            )),
        })
    }

    #[deprecated(since = "0.5.1", note = "please use `into_result` instead")]
    #[allow(clippy::wrong_self_convention)]
    pub fn as_result(self) -> Result<Self> {
        self.into_result()
    }

    /// Converts the object to a [Result]
    pub fn into_result(self) -> Result<Self> {
        match self.err {
            Some(err) => Err(err),
            None => Ok(self),
        }
    }
}
