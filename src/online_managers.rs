// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate rmp_serde;

use std::sync::Arc;
use url::Url;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::encrypted_models::{
    ChunkArrayItem, CollectionAccessLevel, EncryptedCollection, EncryptedItem, EncryptedRevision,
    SignedInvitation,
};
use super::error::{Error, Result};
use super::http_client::Client;
use crate::utils::{StrBase64, StringBase64};

pub fn test_reset(client: &Client, body_struct: SignupBody) -> Result<()> {
    let body = rmp_serde::to_vec_named(&body_struct)?;
    let url = client.api_base.join("api/v1/test/authentication/reset/")?;

    let res = client.post(url.as_str(), body)?;

    res.error_for_status()?;

    Ok(())
}

/// A collection for which the user lost access
///
/// Deleted collections are marked using [`Collection::is_deleted`](crate::Collection::is_deleted).
/// However, when we just lose access
/// to a collection and it hasn't been deleted, we get this object.
#[derive(Deserialize, Clone)]
pub struct RemovedCollection {
    uid: StringBase64,
}

impl RemovedCollection {
    /// The uid of the removed collection
    pub fn uid(&self) -> &StrBase64 {
        &self.uid
    }
}

/// The response of fetching a collection list
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionListResponse<T> {
    pub(crate) data: Vec<T>,
    pub(crate) done: bool,
    pub(crate) stoken: Option<String>,
    pub(crate) removed_memberships: Option<Vec<RemovedCollection>>,
}

impl<T> CollectionListResponse<T> {
    /// Sync token for the list response
    pub fn stoken(&self) -> Option<&str> {
        self.stoken.as_deref()
    }

    /// List of collections included in the response
    pub fn data(&self) -> &Vec<T> {
        &self.data
    }

    /// Indicates whether there are no more collections to fetch
    pub fn done(&self) -> bool {
        self.done
    }

    /// The list of collections to which the user lost access
    pub fn removed_memberships(&self) -> Option<&Vec<RemovedCollection>> {
        self.removed_memberships.as_ref()
    }
}

/// The response of fetching an item list
#[derive(Deserialize)]
pub struct ItemListResponse<T> {
    pub(crate) data: Vec<T>,
    pub(crate) done: bool,
    pub(crate) stoken: Option<String>,
}

impl<T> ItemListResponse<T> {
    /// Sync token for the list response
    pub fn stoken(&self) -> Option<&str> {
        self.stoken.as_deref()
    }

    /// List of items included in the response
    pub fn data(&self) -> &Vec<T> {
        &self.data
    }

    /// Indicates whether there are no more items to fetch
    pub fn done(&self) -> bool {
        self.done
    }
}

/// The response of fetching a list
#[derive(Deserialize)]
pub struct IteratorListResponse<T> {
    pub(crate) data: Vec<T>,
    pub(crate) done: bool,
    pub(crate) iterator: Option<String>,
}

impl<T> IteratorListResponse<T> {
    /// Iterator for the list response
    pub fn iterator(&self) -> Option<&str> {
        self.iterator.as_deref()
    }

    /// List of data items included in the response
    pub fn data(&self) -> &Vec<T> {
        &self.data
    }

    /// Indicates whether there is no more data to fetch
    pub fn done(&self) -> bool {
        self.done
    }
}

#[derive(Deserialize)]
pub struct LoginChallange {
    #[serde(with = "serde_bytes")]
    pub challenge: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    pub version: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignupBody<'a> {
    pub user: &'a User,
    #[serde(with = "serde_bytes")]
    pub salt: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub login_pubkey: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub pubkey: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub encrypted_content: &'a [u8],
}

#[derive(Serialize)]
struct LoginBody<'a> {
    #[serde(with = "serde_bytes")]
    response: &'a [u8],
    #[serde(with = "serde_bytes")]
    signature: &'a [u8],
}

#[derive(Serialize)]
pub struct LoginBodyResponse<'a> {
    pub username: &'a str,
    #[serde(with = "serde_bytes")]
    pub challenge: &'a [u8],
    pub host: &'a str,
    pub action: &'a str,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponseUser {
    pub username: String,
    pub email: String,
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub encrypted_content: Vec<u8>,
}

#[derive(Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: LoginResponseUser,
}

/// A user object
#[derive(Serialize, Deserialize)]
pub struct User {
    username: String,
    email: String,
}

impl User {
    /// Return a new user instance
    ///
    /// # Arguments:
    /// * `username` - the user's username
    /// * `email` - the user's email
    pub fn new(username: &str, email: &str) -> Self {
        Self {
            username: username.to_owned(),
            email: email.to_owned(),
        }
    }

    /// Set the username
    ///
    /// # Arguments:
    /// * `username` - the user's username
    pub fn set_username(&mut self, username: &str) -> &mut Self {
        self.username = username.to_owned();
        self
    }

    /// Get the username
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Set the email address
    ///
    /// # Arguments:
    /// * `email` - the user's email address
    pub fn set_email(&mut self, email: &str) -> &mut Self {
        self.email = email.to_owned();
        self
    }

    /// Get the email address
    pub fn email(&self) -> &str {
        &self.email
    }
}

/// A user's public profile
#[derive(Serialize, Deserialize, Clone)]
pub struct UserProfile {
    #[serde(with = "serde_bytes")]
    pubkey: Vec<u8>,
}

impl UserProfile {
    /// The user's identity public key
    ///
    /// This is used for identifying the user and safely sending them data (such as
    /// [invitations](SignedInvitation)).
    pub fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }
}

pub struct Authenticator<'a> {
    api_base: Url,
    client: &'a Client,
}

impl<'a> Authenticator<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self {
            api_base: client.api_base.join("api/v1/authentication/").unwrap(),
            client,
        }
    }

    pub fn is_etebase_server(&self) -> Result<bool> {
        let url = self.api_base.join("is_etebase/")?;
        let res = self.client.get(url.as_str())?;
        if res.status() == 404 {
            return Ok(false);
        }
        res.error_for_status()?;

        Ok(true)
    }

    pub fn get_login_challenge(&self, username: &str) -> Result<LoginChallange> {
        #[derive(Serialize)]
        struct Body<'a> {
            username: &'a str,
        }

        let body_struct = Body { username };
        let body = rmp_serde::to_vec_named(&body_struct)?;

        let url = self.api_base.join("login_challenge/")?;
        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;
        let res = res.bytes();

        let ret: LoginChallange = rmp_serde::from_read_ref(&res)?;

        Ok(ret)
    }

    pub fn signup(
        &self,
        user: &User,
        salt: &[u8],
        login_pubkey: &[u8],
        pubkey: &[u8],
        encrypted_content: &[u8],
    ) -> Result<LoginResponse> {
        let body_struct = SignupBody {
            user,
            salt,
            login_pubkey,
            pubkey,
            encrypted_content,
        };
        let body = rmp_serde::to_vec_named(&body_struct)?;

        let url = self.api_base.join("signup/")?;
        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;
        let res = res.bytes();

        let ret: LoginResponse = rmp_serde::from_read_ref(&res)?;

        Ok(ret)
    }

    pub fn login(&self, response: &[u8], signature: &[u8]) -> Result<LoginResponse> {
        let body_struct = LoginBody {
            response,
            signature,
        };
        let body = rmp_serde::to_vec_named(&body_struct)?;

        let url = self.api_base.join("login/")?;
        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;
        let res = res.bytes();

        let ret: LoginResponse = rmp_serde::from_read_ref(&res)?;

        Ok(ret)
    }

    pub fn logout(&self) -> Result<()> {
        let url = self.api_base.join("logout/")?;
        let res = self.client.post(url.as_str(), vec![])?;
        res.error_for_status()?;

        Ok(())
    }

    pub fn change_password(&self, response: &[u8], signature: &[u8]) -> Result<()> {
        let body_struct = LoginBody {
            response,
            signature,
        };
        let body = rmp_serde::to_vec_named(&body_struct)?;

        let url = self.api_base.join("change_password/")?;
        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;

        Ok(())
    }

    pub fn fetch_dashboard_url(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct Ret {
            pub url: String,
        }

        let url = self.api_base.join("dashboard_url/")?;
        let res = self.client.post(url.as_str(), vec![])?;
        res.error_for_status()?;
        let res = res.bytes();

        let ret: Ret = rmp_serde::from_read_ref(&res)?;

        Ok(ret.url)
    }
}

/// Dictates how much data to prefetch when passed to [`FetchOptions`]
#[derive(Clone)]
pub enum PrefetchOption {
    /// Automatically decide based on the size of the data fetched
    Auto,
    /// Attempt to fetch a more lightweight (medium) amount of data
    Medium,
}

/// Configuration options for data fetching
#[derive(Default)]
pub struct FetchOptions<'a> {
    limit: Option<usize>,
    stoken: Option<&'a str>,
    iterator: Option<&'a str>,
    prefetch: Option<&'a PrefetchOption>,
    with_collection: Option<bool>,
}

impl<'a> FetchOptions<'a> {
    /// Return a new fetch options object
    pub fn new() -> Self {
        Self::default()
    }

    /// Limit the amount of items returned
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// How much data to prefetech
    pub fn prefetch(mut self, prefetch: &'a PrefetchOption) -> Self {
        self.prefetch = Some(prefetch);
        self
    }

    /// Used by [`ItemManager`](crate::managers::ItemManager) functions to toggle fetching the collection's item
    pub fn with_collection(mut self, with_collection: bool) -> Self {
        self.with_collection = Some(with_collection);
        self
    }

    /// The current iterator to start from (when iterating lists)
    pub fn iterator(mut self, iterator: Option<&'a str>) -> Self {
        self.iterator = iterator;
        self
    }

    /// The sync token to fetch with
    pub fn stoken(mut self, stoken: Option<&'a str>) -> Self {
        self.stoken = stoken;
        self
    }
}

pub fn apply_fetch_options(url: Url, options: Option<&FetchOptions>) -> Url {
    let options = match options {
        Some(options) => options,
        None => return url,
    };

    let mut url = url;
    {
        let mut query = url.query_pairs_mut();
        if let Some(limit) = options.limit {
            query.append_pair("limit", &limit.to_string());
        }
        if let Some(prefetch) = options.prefetch {
            let prefetch = match prefetch {
                PrefetchOption::Auto => "auto",
                PrefetchOption::Medium => "medium",
            };
            query.append_pair("prefetch", prefetch);
        }
        if let Some(with_collection) = options.with_collection {
            query.append_pair("withCollection", &with_collection.to_string());
        }
        if let Some(stoken) = options.stoken {
            query.append_pair("stoken", stoken);
        }
        if let Some(iterator) = options.iterator {
            query.append_pair("iterator", iterator);
        }
    }

    url
}

pub struct CollectionManagerOnline {
    api_base: Url,
    client: Arc<Client>,
}

impl CollectionManagerOnline {
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            api_base: client.api_base.join("api/v1/collection/").unwrap(),
            client,
        }
    }

    pub fn fetch(
        &self,
        col_uid: &str,
        options: Option<&FetchOptions>,
    ) -> Result<EncryptedCollection> {
        let url = apply_fetch_options(self.api_base.join(&format!("{}/", col_uid))?, options);
        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: EncryptedCollection = rmp_serde::from_read_ref(&res)?;
        serialized.mark_saved();

        Ok(serialized)
    }

    pub fn list_multi<I>(
        &self,
        collection_types: I,
        options: Option<&FetchOptions>,
    ) -> Result<CollectionListResponse<EncryptedCollection>>
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        let url = apply_fetch_options(self.api_base.join("list_multi/")?, options);

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body {
            collection_types: Vec<ByteBuf>,
        }

        let collection_types = collection_types.into_iter().map(ByteBuf::from).collect();

        let body_struct = Body { collection_types };
        let body = rmp_serde::to_vec_named(&body_struct)?;

        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: CollectionListResponse<EncryptedCollection> =
            rmp_serde::from_read_ref(&res)?;
        serialized.data.iter().for_each(|x| x.mark_saved());

        Ok(serialized)
    }

    pub fn create(
        &self,
        collection: &EncryptedCollection,
        options: Option<&FetchOptions>,
    ) -> Result<()> {
        let url = apply_fetch_options(self.api_base.clone(), options);
        let body = rmp_serde::to_vec_named(&collection)?;

        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;

        collection.mark_saved();

        Ok(())
    }
}

#[derive(Serialize)]
struct ItemBatchBodyDep<'a> {
    uid: &'a str,
    #[serde(skip_serializing_if = "std::option::Option::is_none")]
    etag: Option<String>,
}

#[derive(Serialize)]
struct ItemBatchBody<'a> {
    items: &'a Vec<&'a EncryptedItem>,
    deps: Option<Vec<ItemBatchBodyDep<'a>>>,
}

pub struct ItemManagerOnline {
    api_base: Url,
    client: Arc<Client>,
}

impl ItemManagerOnline {
    pub fn new(client: Arc<Client>, col: &EncryptedCollection) -> Self {
        Self {
            api_base: client
                .api_base
                .join(&format!("api/v1/collection/{}/item/", col.uid()))
                .unwrap(),
            client,
        }
    }

    pub fn fetch(&self, item_uid: &str, options: Option<&FetchOptions>) -> Result<EncryptedItem> {
        let url = apply_fetch_options(self.api_base.join(&format!("{}/", item_uid))?, options);
        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: EncryptedItem = rmp_serde::from_read_ref(&res)?;
        serialized.mark_saved();

        Ok(serialized)
    }

    pub fn list(&self, options: Option<&FetchOptions>) -> Result<ItemListResponse<EncryptedItem>> {
        let url = apply_fetch_options(self.api_base.clone(), options);
        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: ItemListResponse<EncryptedItem> = rmp_serde::from_read_ref(&res)?;
        serialized.data.iter().for_each(|x| x.mark_saved());

        Ok(serialized)
    }

    pub fn item_revisions(
        &self,
        item: &EncryptedItem,
        options: Option<&FetchOptions>,
    ) -> Result<IteratorListResponse<EncryptedItem>> {
        let url = apply_fetch_options(
            self.api_base.join(&format!("{}/revision/", item.uid()))?,
            options,
        );
        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;
        let res = res.bytes();

        let response: IteratorListResponse<EncryptedRevision> = rmp_serde::from_read_ref(&res)?;

        let data: Vec<EncryptedItem> = response
            .data
            .into_iter()
            .map(|x| item.clone_with_revision(x))
            .collect();

        Ok(IteratorListResponse {
            data,
            done: response.done,
            iterator: response.iterator,
        })
    }

    pub fn fetch_updates<'a, I>(
        &self,
        items: I,
        options: Option<&FetchOptions>,
    ) -> Result<ItemListResponse<EncryptedItem>>
    where
        I: Iterator<Item = &'a EncryptedItem>,
    {
        let want_etag = options.and_then(|x| x.stoken).is_none();
        let items: Vec<ItemBatchBodyDep> = items
            .map(|x| ItemBatchBodyDep {
                uid: x.uid(),
                etag: if want_etag { x.last_etag() } else { None },
            })
            .collect();

        let body = rmp_serde::to_vec_named(&items)?;
        let url = apply_fetch_options(self.api_base.join("fetch_updates/")?, options);
        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: ItemListResponse<EncryptedItem> = rmp_serde::from_read_ref(&res)?;
        serialized.data.iter().for_each(|x| x.mark_saved());

        Ok(serialized)
    }

    pub fn fetch_multi<'a, I>(
        &self,
        items: I,
        options: Option<&FetchOptions>,
    ) -> Result<ItemListResponse<EncryptedItem>>
    where
        I: Iterator<Item = &'a StrBase64>,
    {
        let items: Vec<ItemBatchBodyDep> = items
            .map(|x| ItemBatchBodyDep { uid: x, etag: None })
            .collect();

        let body = rmp_serde::to_vec_named(&items)?;
        let url = apply_fetch_options(self.api_base.join("fetch_updates/")?, options);
        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: ItemListResponse<EncryptedItem> = rmp_serde::from_read_ref(&res)?;
        serialized.data.iter().for_each(|x| x.mark_saved());

        Ok(serialized)
    }

    pub fn batch<'a, I, J>(&self, items: I, deps: J, options: Option<&FetchOptions>) -> Result<()>
    where
        I: Iterator<Item = &'a EncryptedItem>,
        J: Iterator<Item = &'a EncryptedItem>,
    {
        let url = apply_fetch_options(self.api_base.join("batch/")?, options);

        let items: Vec<&EncryptedItem> = items.collect();
        let deps: Vec<ItemBatchBodyDep> = deps
            .map(|x| ItemBatchBodyDep {
                uid: x.uid(),
                etag: x.last_etag(),
            })
            .collect();
        let deps = if !deps.is_empty() { Some(deps) } else { None };
        let body_struct = ItemBatchBody {
            items: &items,
            deps,
        };
        let body = rmp_serde::to_vec_named(&body_struct)?;

        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;

        for item in items {
            item.mark_saved();
        }

        Ok(())
    }

    pub fn transaction<'a, I, J>(
        &self,
        items: I,
        deps: J,
        options: Option<&FetchOptions>,
    ) -> Result<()>
    where
        I: Iterator<Item = &'a EncryptedItem>,
        J: Iterator<Item = &'a EncryptedItem>,
    {
        let url = apply_fetch_options(self.api_base.join("transaction/")?, options);

        let items: Vec<&EncryptedItem> = items.collect();
        let deps: Vec<ItemBatchBodyDep> = deps
            .map(|x| ItemBatchBodyDep {
                uid: x.uid(),
                etag: x.last_etag(),
            })
            .collect();
        let deps = if !deps.is_empty() { Some(deps) } else { None };
        let body_struct = ItemBatchBody {
            items: &items,
            deps,
        };
        let body = rmp_serde::to_vec_named(&body_struct)?;

        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;

        for item in items {
            item.mark_saved();
        }

        Ok(())
    }

    pub(crate) fn chunk_upload(
        &self,
        item: &EncryptedItem,
        chunk: &ChunkArrayItem,
        options: Option<&FetchOptions>,
    ) -> Result<()> {
        let chunk_uid = &chunk.0;
        let chunk_content = match &chunk.1 {
            Some(content) => content,
            None => return Err(Error::ProgrammingError("Tried uploading a missing chunk.")),
        };

        let url = apply_fetch_options(
            self.api_base
                .join(&format!("{}/chunk/{}/", item.uid(), chunk_uid))?,
            options,
        );
        // FIXME: We are copying the vec here, we shouldn't! Fix the client.
        let res = self.client.put(url.as_str(), chunk_content.to_vec())?;
        res.error_for_status()?;

        Ok(())
    }

    pub(crate) fn chunk_download(
        &self,
        item_uid: &str,
        chunk_uid: &str,
        options: Option<&FetchOptions>,
    ) -> Result<Vec<u8>> {
        let url = apply_fetch_options(
            self.api_base
                .join(&format!("{}/chunk/{}/download/", item_uid, chunk_uid))?,
            options,
        );
        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;

        Ok(res.bytes().to_vec())
    }
}

/// A member of a collection
///
/// Obtained using [`CollectionManager::list`](crate::managers::CollectionManager::list)
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CollectionMember {
    username: String,
    access_level: CollectionAccessLevel,
}

impl CollectionMember {
    /// The username of a member
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The access level of the member
    pub fn access_level(&self) -> CollectionAccessLevel {
        self.access_level
    }
}

pub struct CollectionInvitationManagerOnline {
    api_base: Url,
    client: Arc<Client>,
}

impl CollectionInvitationManagerOnline {
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            api_base: client.api_base.join("api/v1/invitation/").unwrap(),
            client,
        }
    }

    pub fn list_incoming(
        &self,
        options: Option<&FetchOptions>,
    ) -> Result<IteratorListResponse<SignedInvitation>> {
        let url = apply_fetch_options(self.api_base.join("incoming/")?, options);
        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: IteratorListResponse<SignedInvitation> = rmp_serde::from_read_ref(&res)?;

        Ok(serialized)
    }

    pub fn list_outgoing(
        &self,
        options: Option<&FetchOptions>,
    ) -> Result<IteratorListResponse<SignedInvitation>> {
        let url = apply_fetch_options(self.api_base.join("outgoing/")?, options);
        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: IteratorListResponse<SignedInvitation> = rmp_serde::from_read_ref(&res)?;

        Ok(serialized)
    }

    pub fn accept(
        &self,
        invitation: &SignedInvitation,
        collection_type: &[u8],
        encryption_key: &[u8],
    ) -> Result<()> {
        let url = self
            .api_base
            .join(&format!("incoming/{}/accept/", invitation.uid()))?;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            #[serde(with = "serde_bytes")]
            encryption_key: &'a [u8],
            #[serde(with = "serde_bytes")]
            collection_type: &'a [u8],
        }

        let body_struct = Body {
            encryption_key,
            collection_type,
        };
        let body = rmp_serde::to_vec_named(&body_struct)?;

        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;

        Ok(())
    }

    pub fn reject(&self, invitation: &SignedInvitation) -> Result<()> {
        let url = self
            .api_base
            .join(&format!("incoming/{}/", invitation.uid()))?;

        let res = self.client.delete(url.as_str())?;
        res.error_for_status()?;

        Ok(())
    }

    pub fn fetch_user_profile(&self, username: &str) -> Result<UserProfile> {
        let mut url = self.api_base.join("outgoing/fetch_user_profile/")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("username", username);
        }

        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: UserProfile = rmp_serde::from_read_ref(&res)?;

        Ok(serialized)
    }

    pub fn invite(&self, invitation: &SignedInvitation) -> Result<()> {
        let url = self.api_base.join("outgoing/")?;

        let body = rmp_serde::to_vec_named(&invitation)?;

        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;

        Ok(())
    }

    pub fn disinvite(&self, invitation: &SignedInvitation) -> Result<()> {
        let url = self
            .api_base
            .join(&format!("outgoing/{}/", invitation.uid()))?;

        let res = self.client.delete(url.as_str())?;
        res.error_for_status()?;

        Ok(())
    }
}

pub struct CollectionMemberManagerOnline {
    api_base: Url,
    client: Arc<Client>,
}

impl CollectionMemberManagerOnline {
    pub fn new(client: Arc<Client>, collection: &EncryptedCollection) -> Self {
        Self {
            api_base: client
                .api_base
                .join(&format!("api/v1/collection/{}/member/", collection.uid()))
                .unwrap(),
            client,
        }
    }

    pub fn list(
        &self,
        options: Option<&FetchOptions>,
    ) -> Result<IteratorListResponse<CollectionMember>> {
        let url = apply_fetch_options(self.api_base.clone(), options);
        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: IteratorListResponse<CollectionMember> = rmp_serde::from_read_ref(&res)?;

        Ok(serialized)
    }

    pub fn remove(&self, username: &str) -> Result<()> {
        let url = self.api_base.join(&format!("{}/", username))?;

        let res = self.client.delete(url.as_str())?;
        res.error_for_status()?;

        Ok(())
    }

    pub fn leave(&self) -> Result<()> {
        let url = self.api_base.join("leave/")?;

        let res = self.client.post(url.as_str(), vec![])?;
        res.error_for_status()?;

        Ok(())
    }

    pub fn modify_access_level(
        &self,
        username: &str,
        access_level: CollectionAccessLevel,
    ) -> Result<()> {
        let url = self.api_base.join(&format!("{}/", username))?;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body {
            access_level: CollectionAccessLevel,
        }

        let body_struct = Body { access_level };
        let body = rmp_serde::to_vec_named(&body_struct)?;

        let res = self.client.patch(url.as_str(), body)?;
        res.error_for_status()?;

        Ok(())
    }
}
