// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate openssl;
extern crate base64;

pub mod crypto;
pub mod service;
pub mod content;
pub mod error;

pub use error::Error;

mod capi;
