// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

mod crypto;
mod chunker;
mod http_client;
mod online_managers;
mod encrypted_models;
mod service;
pub mod fs_cache;
pub mod utils;
pub mod error;

pub use crypto::pretty_fingerprint;

pub use http_client::Client;

pub mod http_custom_client {
    pub use crate::http_client::{
        ClientImplementation,
        Response,
    };
}

pub use online_managers::{
    User,
    UserProfile,
    CollectionMember,
    PrefetchOption,
    FetchOptions,
    CollectionListResponse,
    ItemListResponse,
    IteratorListResponse,

    RemovedCollection,
};

pub use encrypted_models::{
    CollectionAccessLevel,
    ItemMetadata,
    SignedInvitation,
};

pub use service::{
    Account,
    Collection,
    Item,
};

pub mod managers {
    pub use super::service::{
        CollectionManager,
        ItemManager,
        CollectionMemberManager,
        CollectionInvitationManager,
    };
}

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

        pub fn test_buffer_pad_fixed(buf: &[u8], blocksize: usize) -> Result<Vec<u8>> {
            buffer_pad_fixed(buf, blocksize)
        }

        pub fn test_buffer_unpad_fixed(buf: &[u8], blocksize: usize) -> Result<Vec<u8>> {
            buffer_unpad_fixed(buf, blocksize)
        }
    }
    pub use super::online_managers::{
        // Test stuff
        test_reset,
        SignupBody,
    };

    pub fn chunk_uids(item: &super::service::Item) -> Vec<String> {
        super::service::test_chunk_uids(item)
    }
}

pub const CURRENT_VERSION: u8 = 1;
pub const DEFAULT_SERVER_URL: &str = "https://api.etebase.com";

pub use error::Error;

pub fn init() -> error::Result<()> {
    crypto::init()
}
