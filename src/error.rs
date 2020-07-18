// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::error;
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum Error {
    Generic(String),
    Encoding(String),
    Integrity(&'static str),
    Encryption(String),
    EncryptionMac(&'static str),
    PermissionDenied(&'static str),
    InvalidData(&'static str),
    Unauthorized(String),
    NotFound(String),
    Conflict(String),

    Connection(String),
    Http(String),
    Json(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Generic(s) => s.fmt(f),
            Error::Encoding(s) => s.fmt(f),
            Error::Integrity(s) => s.fmt(f),
            Error::Encryption(s) => s.fmt(f),
            Error::EncryptionMac(s) => s.fmt(f),
            Error::PermissionDenied(s) => s.fmt(f),
            Error::InvalidData(s) => s.fmt(f),
            Error::Unauthorized(s) => s.fmt(f),
            Error::NotFound(s) => s.fmt(f),
            Error::Conflict(s) => s.fmt(f),

            Error::Connection(s) => s.fmt(f),
            Error::Http(s) => s.fmt(f),
            Error::Json(s) => s.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error::Generic(err)
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        if err.is_status() {
            match err.status() {
                Some(reqwest::StatusCode::UNAUTHORIZED) => Error::Unauthorized(err.to_string()),
                Some(reqwest::StatusCode::NOT_FOUND) => Error::NotFound(err.to_string()),
                Some(reqwest::StatusCode::CONFLICT) => Error::Conflict(err.to_string()),
                _ => Error::Http(err.to_string()),
            }
        } else if err.is_builder() || err.is_timeout() || err.is_redirect() {
            Error::Generic(err.to_string())
        } else {
            Error::Connection(err.to_string())
        }
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Error {
        Error::Encoding(err.to_string())
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Error {
        Error::Encryption(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        Error::Json(err.to_string())
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(err: std::ffi::NulError) -> Error {
        Error::Generic(err.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Error {
        Error::Encoding(err.to_string())
    }
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Error {
        Error::Encoding(err.to_string())
    }
}
