// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

#![warn(clippy::all)]

mod chunker;
mod crypto;
mod encrypted_models;
pub mod error;
pub mod fs_cache;
mod http_client;
mod online_managers;
mod service;
pub mod utils;

pub use crypto::pretty_fingerprint;

pub use http_client::Client;

pub mod http_custom_client {
    pub use crate::http_client::{ClientImplementation, Response};
}

pub use online_managers::{
    CollectionListResponse, CollectionMember, FetchOptions, ItemListResponse, IteratorListResponse,
    PrefetchOption, RemovedCollection, User, UserProfile,
};

pub use encrypted_models::{CollectionAccessLevel, ItemMetadata, SignedInvitation};

pub use service::{Account, Collection, Item};

pub mod managers {
    pub use super::service::{
        CollectionInvitationManager, CollectionManager, CollectionMemberManager, ItemManager,
    };
}

#[doc(hidden)]
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
pub const DEFAULT_SERVER_URL: &str = "https://api.etebase.com/";

pub fn init() -> error::Result<()> {
    crypto::init()
}
