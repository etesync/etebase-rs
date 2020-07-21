// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

mod crypto;
mod online_managers;
mod encrypted_models;
mod service;
pub mod utils;
pub mod error;

pub use online_managers::{
    Client,
    User,
};

pub use encrypted_models::{
    CollectionMetadata,
    ItemMetadata,
};

pub use service::{
    Account,
    Collection,
    Item,
};

pub mod test_helpers {
    pub use super::online_managers::{
        // Test stuff
        test_reset,
        SignupBody,
    };
}

pub const CURRENT_VERSION: u8 = 1;
pub const API_URL: &str = "https://api.etebase.com";

pub use error::Error;

pub fn init() -> error::Result<()> {
    crypto::init()
}

mod capi;
