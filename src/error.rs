// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::error;
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum Error {
    Generic(String),
    UrlParse(String),
    MsgPackEncode(String),
    MsgPackDecode(String),
    ProgrammingError(&'static str),
    Padding(&'static str),
    Base64(&'static str),
    TryInto(&'static str),
    Integrity(String),
    Encryption(&'static str),
    EncryptionMac(&'static str),
    PermissionDenied(&'static str),
    InvalidData(&'static str),
    Unauthorized(String),
    Conflict(String),

    Connection(String),
    Http(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Generic(s) => s.fmt(f),
            Error::UrlParse(s) => s.fmt(f),
            Error::MsgPackEncode(s) => s.fmt(f),
            Error::MsgPackDecode(s) => s.fmt(f),
            Error::ProgrammingError(s) => s.fmt(f),
            Error::Padding(s) => s.fmt(f),
            Error::Base64(s) => s.fmt(f),
            Error::TryInto(s) => s.fmt(f),
            Error::Integrity(s) => s.fmt(f),
            Error::Encryption(s) => s.fmt(f),
            Error::EncryptionMac(s) => s.fmt(f),
            Error::PermissionDenied(s) => s.fmt(f),
            Error::InvalidData(s) => s.fmt(f),
            Error::Unauthorized(s) => s.fmt(f),
            Error::Conflict(s) => s.fmt(f),

            Error::Connection(s) => s.fmt(f),
            Error::Http(s) => s.fmt(f),
        }
    }
}

impl From<Error> for String {
    fn from(err: Error) -> String {
        err.to_string()
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
        Error::UrlParse(err.to_string())
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(err: std::ffi::NulError) -> Error {
        Error::Generic(err.to_string())
    }
}

impl From<block_padding::PadError> for Error {
    fn from(_err: block_padding::PadError) -> Error {
        Error::Padding("Failed padding")
    }
}

impl From<block_padding::UnpadError> for Error {
    fn from(_err: block_padding::UnpadError) -> Error {
        Error::Padding("Failed unpadding")
    }
}

impl From<rmp_serde::encode::Error> for Error {
    fn from(err: rmp_serde::encode::Error) -> Error {
        Error::MsgPackEncode(err.to_string())
    }
}

impl From<rmp_serde::decode::Error> for Error {
    fn from(err: rmp_serde::decode::Error) -> Error {
        Error::MsgPackDecode(err.to_string())
    }
}
