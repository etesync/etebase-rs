// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate rmp_serde;

use std::sync::Arc;
use url::Url;

use serde::{Serialize, Deserialize};

use super::error::Result;
use super::http_client::Client;
use crate::utils::{
    StrBase64,
    StringBase64,
};
use super::encrypted_models::{
    CollectionAccessLevel,
    EncryptedCollection,
    EncryptedItem,
    EncryptedRevision,
    SignedInvitation,
};

pub fn test_reset(client: &Client, body_struct: SignupBody) -> Result<()> {
    let body = rmp_serde::to_vec_named(&body_struct)?;
    let url = client.api_base.join("api/v1/test/authentication/reset/")?;

    let res = client.post(url.as_str(), body)?;

    res.error_for_status()?;

    Ok(())
}

#[derive(Deserialize, Clone)]
pub struct RemovedCollection {
    uid: StringBase64,
}

impl RemovedCollection {
    pub fn uid(&self) -> &StrBase64 {
        &self.uid
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionListResponse<T> {
    pub(crate) data: Vec<T>,
    pub(crate) done: bool,
    pub(crate) stoken: Option<String>,
    pub(crate) removed_memberships: Option<Vec<RemovedCollection>>,
}

impl<T> CollectionListResponse<T> {
    pub fn stoken(&self) -> Option<&str> {
        self.stoken.as_deref()
    }

    pub fn data(&self) -> &Vec<T> {
        &self.data
    }

    pub fn done(&self) -> bool {
        self.done
    }
    pub fn removed_memberships(&self) -> Option<&Vec<RemovedCollection>> {
        self.removed_memberships.as_ref()
    }

}

#[derive(Deserialize)]
pub struct ItemListResponse<T> {
    pub(crate) data: Vec<T>,
    pub(crate) done: bool,
    pub(crate) stoken: Option<String>,
}

impl<T> ItemListResponse<T> {
    pub fn stoken(&self) -> Option<&str> {
        self.stoken.as_deref()
    }

    pub fn data(&self) -> &Vec<T> {
        &self.data
    }

    pub fn done(&self) -> bool {
        self.done
    }
}

#[derive(Deserialize)]
pub struct IteratorListResponse<T> {
    pub(crate) data: Vec<T>,
    pub(crate) done: bool,
    pub(crate) iterator: Option<String>,
}

impl<T> IteratorListResponse<T> {
    pub fn iterator(&self) -> Option<&str> {
        self.iterator.as_deref()
    }

    pub fn data(&self) -> &Vec<T> {
        &self.data
    }

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
    pub salt: &'a[u8],
    #[serde(with = "serde_bytes")]
    pub login_pubkey: &'a[u8],
    #[serde(with = "serde_bytes")]
    pub pubkey: &'a[u8],
    #[serde(with = "serde_bytes")]
    pub encrypted_content: &'a[u8],
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

#[derive(Serialize, Deserialize)]
pub struct User {
    username: String,
    email: String,
}

impl User {
    pub fn new(username: &str, email: &str) -> Self {
        Self {
            username: username.to_owned(),
            email: email.to_owned(),
        }
    }

    pub fn set_username(&mut self, username: &str) -> &mut Self {
        self.username = username.to_owned();
        self
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn set_email(&mut self, email: &str) -> &mut Self {
        self.email = email.to_owned();
        self
    }

    pub fn email(&self) -> &str {
        &self.email
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UserProfile {
    #[serde(with = "serde_bytes")]
    pubkey: Vec<u8>,
}

impl UserProfile {
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

        let body_struct = Body {
            username,
        };
        let body = rmp_serde::to_vec_named(&body_struct)?;

        let url = self.api_base.join("login_challenge/")?;
        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;
        let res = res.bytes();

        let ret: LoginChallange = rmp_serde::from_read_ref(&res)?;

        Ok(ret)
    }

    pub fn signup(&self, user: &User, salt: &[u8], login_pubkey: &[u8], pubkey: &[u8], encrypted_content: &[u8]) -> Result<LoginResponse> {
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
}

#[derive(Clone)]
pub enum PrefetchOption {
    Auto,
    Medium,
}

pub struct FetchOptions<'a> {
    limit: Option<usize>,
    stoken: Option<&'a str>,
    iterator: Option<&'a str>,
    prefetch: Option<&'a PrefetchOption>,
    with_collection: Option<bool>,
}

impl<'a> FetchOptions<'a> {
    pub fn new() -> Self {
        Self {
            limit: None,
            stoken: None,
            iterator: None,
            prefetch: None,
            with_collection: None,
        }
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn prefetch(mut self, prefetch: &'a PrefetchOption) -> Self {
        self.prefetch = Some(prefetch);
        self
    }

    pub fn with_collection(mut self, with_collection: bool) -> Self {
        self.with_collection = Some(with_collection);
        self
    }

    pub fn iterator(mut self, iterator: Option<&'a str>) -> Self {
        self.iterator = iterator;
        self
    }

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

    pub fn fetch(&self, col_uid: &str, options: Option<&FetchOptions>) -> Result<EncryptedCollection> {
        let url = apply_fetch_options(self.api_base.join(&format!("{}/", col_uid))?, options);
        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: EncryptedCollection = rmp_serde::from_read_ref(&res)?;
        serialized.mark_saved();

        Ok(serialized)
    }

    pub fn list(&self, options: Option<&FetchOptions>) -> Result<CollectionListResponse<EncryptedCollection>> {
        let url = apply_fetch_options(self.api_base.clone(), options);
        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: CollectionListResponse<EncryptedCollection> = rmp_serde::from_read_ref(&res)?;
        serialized.data.iter().for_each(|x| x.mark_saved());

        Ok(serialized)
    }

    pub fn create(&self, collection: &EncryptedCollection, options: Option<&FetchOptions>) -> Result<()> {
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
            api_base: client.api_base.join(&format!("api/v1/collection/{}/item/", col.uid())).unwrap(),
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

    pub fn item_revisions(&self, item: &EncryptedItem, options: Option<&FetchOptions>) -> Result<IteratorListResponse<EncryptedItem>> {
        let url = apply_fetch_options(self.api_base.join(&format!("{}/revision/", item.uid()))?, options);
        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;
        let res = res.bytes();

        let response: IteratorListResponse<EncryptedRevision> = rmp_serde::from_read_ref(&res)?;

        let data: Vec<EncryptedItem> = response.data.into_iter()
            .map(|x| {
                item.clone_with_revision(x)
            })
        .collect();

        Ok(IteratorListResponse {
            data,
            done: response.done,
            iterator: response.iterator,
        })
    }

    pub fn fetch_updates<'a, I>(&self, items: I, options: Option<&FetchOptions>) -> Result<ItemListResponse<EncryptedItem>>
        where I: Iterator<Item = &'a EncryptedItem>
        {

            let want_etag = options.and_then(|x| x.stoken).is_none();
            let items: Vec<ItemBatchBodyDep> = items.map(|x| {
                ItemBatchBodyDep {
                    uid: x.uid(),
                    etag: if want_etag {
                        x.last_etag()
                    } else {
                        None
                    }
                }
            }).collect();

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
        where I: Iterator<Item = &'a EncryptedItem>, J: Iterator<Item = &'a EncryptedItem>
        {

            let url = apply_fetch_options(self.api_base.join("batch/")?, options);

            let items: Vec<&EncryptedItem> = items.collect();
            let deps: Vec<ItemBatchBodyDep> = deps.map(|x| {
                ItemBatchBodyDep {
                    uid: x.uid(),
                    etag: x.last_etag(),
                }
            }).collect();
            let deps = if deps.len() > 0 {
                Some(deps)
            } else {
                None
            };
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

    pub fn transaction<'a, I, J>(&self, items: I, deps: J, options: Option<&FetchOptions>) -> Result<()>
        where I: Iterator<Item = &'a EncryptedItem>, J: Iterator<Item = &'a EncryptedItem>
        {

            let url = apply_fetch_options(self.api_base.join("transaction/")?, options);

            let items: Vec<&EncryptedItem> = items.collect();
            let deps: Vec<ItemBatchBodyDep> = deps.map(|x| {
                ItemBatchBodyDep {
                    uid: x.uid(),
                    etag: x.last_etag(),
                }
            }).collect();
            let deps = if deps.len() > 0 {
                Some(deps)
            } else {
                None
            };
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
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CollectionMember {
    username: String,
    access_level: CollectionAccessLevel,
}

impl CollectionMember {
    pub fn username(&self) -> &str {
        &self.username
    }

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

    pub fn list_incoming(&self, options: Option<&FetchOptions>) -> Result<IteratorListResponse<SignedInvitation>> {
        let url = apply_fetch_options(self.api_base.join("incoming/")?, options);
        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: IteratorListResponse<SignedInvitation> = rmp_serde::from_read_ref(&res)?;

        Ok(serialized)
    }

    pub fn list_outgoing(&self, options: Option<&FetchOptions>) -> Result<IteratorListResponse<SignedInvitation>> {
        let url = apply_fetch_options(self.api_base.join("outgoing/")?, options);
        let res = self.client.get(url.as_str())?;
        res.error_for_status()?;
        let res = res.bytes();

        let serialized: IteratorListResponse<SignedInvitation> = rmp_serde::from_read_ref(&res)?;

        Ok(serialized)
    }

    pub fn accept(&self, invitation: &SignedInvitation, encryption_key: &[u8]) -> Result<()> {
        let url = self.api_base.join(&format!("incoming/{}/accept/", invitation.uid()))?;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            #[serde(with = "serde_bytes")]
            encryption_key: &'a [u8],
        }

        let body_struct = Body {
            encryption_key,
        };
        let body = rmp_serde::to_vec_named(&body_struct)?;

        let res = self.client.post(url.as_str(), body)?;
        res.error_for_status()?;

        Ok(())
    }

    pub fn reject(&self, invitation: &SignedInvitation) -> Result<()> {
        let url = self.api_base.join(&format!("incoming/{}/", invitation.uid()))?;

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
        let url = self.api_base.join(&format!("outgoing/{}/", invitation.uid()))?;

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
            api_base: client.api_base.join(&format!("api/v1/collection/{}/member/", collection.uid())).unwrap(),
            client,
        }
    }

    pub fn list(&self, options: Option<&FetchOptions>) -> Result<IteratorListResponse<CollectionMember>> {
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

    pub fn modify_access_level(&self, username: &str, access_level: CollectionAccessLevel) -> Result<()> {
        let url = self.api_base.join(&format!("{}/", username))?;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body {
            access_level: CollectionAccessLevel,
        }

        let body_struct = Body {
            access_level,
        };
        let body = rmp_serde::to_vec_named(&body_struct)?;

        let res = self.client.patch(url.as_str(), body)?;
        res.error_for_status()?;

        Ok(())
    }
}
