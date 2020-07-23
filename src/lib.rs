// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

mod crypto;
mod chunker;
mod online_managers;
mod encrypted_models;
mod service;
pub mod utils;
pub mod error;

pub use online_managers::{
    Client,
    User,
    FetchOptions,
    CollectionListResponse,
    ItemListResponse,
    IteratorListResponse,
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
    pub mod crypto {
        pub use super::super::crypto::*;
    }
    pub mod utils {
        use super::super::error::Result;

        pub use super::super::utils::*;
        pub fn test_buffer_pad(buf: &[u8]) -> Result<Vec<u8>> {
            buffer_pad(buf)
        }

        pub fn test_buffer_unpad(buf: &[u8]) -> Result<Vec<u8>> {
            buffer_unpad(buf)
        }
    }
    pub use super::online_managers::{
        // Test stuff
        test_reset,
        SignupBody,
    };

    pub fn get_chunk_uids(item: &super::service::Item) -> Vec<String> {
        super::service::test_get_chunk_uids(item)
    }
}

pub const CURRENT_VERSION: u8 = 1;
pub const API_URL: &str = "https://api.etebase.com";

pub use error::Error;

pub fn init() -> error::Result<()> {
    crypto::init()
}

mod capi;
