// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

#![warn(clippy::all)]
#![allow(clippy::unnecessary_wraps)]

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

/// Helper functions for integration tests. Any items in this module is not considered part of the
/// public API and may change at any time.
#[doc(hidden)]
pub mod test_helpers {
    pub use super::{online_managers::test_reset, service::test_chunk_uids as chunk_uids};
}

pub const CURRENT_VERSION: u8 = 1;
pub const DEFAULT_SERVER_URL: &str = "https://api.etebase.com/";

pub fn init() -> error::Result<()> {
    crypto::init()
}
