// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

pub mod crypto;
pub mod online_managers; // FIXME: make private
pub mod service;
pub mod content;
pub mod utils;
pub mod error;

pub use online_managers::Client;

pub const CURRENT_VERSION: u8 = 1;

pub use error::Error;

pub fn init() -> error::Result<()> {
    crypto::init()
}

mod capi;
