// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate rmp_serde;

use std::rc::Rc;
use url::Url;

use serde::{Serialize, Deserialize};

use reqwest::{
    blocking:: {
        Client as ReqwestClient,
        RequestBuilder,
    },
    header,
};

use super::error::Result;

use super::encrypted_models::{
    EncryptedCollection,
    EncryptedItem,
};

static APP_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
);

pub fn test_reset(client: &Client, body_struct: SignupBody) -> Result<()> {
    let body = rmp_serde::to_vec_named(&body_struct)?;
    let url = client.api_base.join("api/v1/test/authentication/reset/")?;

    let res = client.post(&url)?
        .body(body)
        .send()?;

    res.error_for_status()?;

    Ok(())
}

#[derive(Clone)]
pub struct Client {
    req_client: ReqwestClient,
    auth_token: Option<String>,
    api_base: Url,
}

impl Client {
    pub fn new(client_name: &str, server_url: &str) -> Result<Self> {
        let req_client = ReqwestClient::builder()
            .user_agent(format!("{} {}", client_name, APP_USER_AGENT))
            .build()?;

        Ok(Self{
            req_client,
            api_base: Url::parse(server_url)?,
            auth_token: None,
        })
    }

    pub fn set_token(&mut self, token: Option<&str>) {
        self.auth_token = token.and_then(|x| Some(x.to_string()));
    }

    pub fn get_token<'a>(&'a self) -> Option<&'a str> {
        self.auth_token.as_deref().and_then(|x| Some(&x[..]))
    }

    pub fn set_api_base(&mut self, server_url: &str) -> Result<()> {
        self.api_base = Url::parse(server_url)?;

        Ok(())
    }

    pub fn get_api_base(&self) -> &Url {
        &self.api_base
    }

    fn with_auth_header(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth_token {
            Some(auth_token) => builder.header(header::AUTHORIZATION, format!("Token {}", auth_token)),
            None => builder,
        }
    }

    fn with_base_headers(&self, builder: RequestBuilder) -> RequestBuilder {
        builder
            .header(header::CONTENT_TYPE, "application/msgpack")
            .header(header::ACCEPT, "application/msgpack")
    }

    fn prep_client(&self, builder: RequestBuilder) -> RequestBuilder {
        self.with_base_headers(self.with_auth_header(builder))
    }

    pub fn get(&self, url: &Url) -> Result<RequestBuilder> {
        Ok(self.prep_client(self.req_client.get(url.as_str())))
    }

    pub fn post(&self, url: &Url) -> Result<RequestBuilder> {
        Ok(self.prep_client(self.req_client.post(url.as_str())))
    }

    pub fn put(&self, url: &Url) -> Result<RequestBuilder> {
        Ok(self.prep_client(self.req_client.put(url.as_str())))
    }

    pub fn delete(&self, url: &Url) -> Result<RequestBuilder> {
        Ok(self.prep_client(self.req_client.delete(url.as_str())))
    }
}

#[derive(Deserialize)]
pub struct ListResponse<T> {
    pub data: Vec<T>,
    pub done: bool,
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
    pub user: &'a User<'a>,
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
pub struct User<'a> {
    pub username: &'a str,
    pub email: &'a str,
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
        let res = self.client.post(&url)?
            .body(body)
            .send()?;
        let res = res.error_for_status()?.bytes()?;

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
        let res = self.client.post(&url)?
            .body(body)
            .send()?;
        let res = res.error_for_status()?.bytes()?;

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
        let res = self.client.post(&url)?
            .body(body)
            .send()?;
        let res = res.error_for_status()?.bytes()?;

        let ret: LoginResponse = rmp_serde::from_read_ref(&res)?;

        Ok(ret)
    }

    pub fn logout(&self) -> Result<()> {
        let url = self.api_base.join("logout/")?;
        let res = self.client.post(&url)?
            .send()?;
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
        let res = self.client.post(&url)?
            .body(body)
            .send()?;
        res.error_for_status()?;

        Ok(())
    }
}

pub struct FetchOptions<'a> {
    limit: Option<usize>,
    stoken: Option<&'a str>,
    iterator: Option<&'a str>,
    prefetch: Option<bool>,
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

    pub fn prefetch(mut self, prefetch: bool) -> Self {
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
            query.append_pair("prefetch", &prefetch.to_string());
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
    client: Rc<Client>,
}

impl CollectionManagerOnline {
    pub fn new(client: Rc<Client>) -> Self {
        Self {
            api_base: client.api_base.join("api/v1/collection/").unwrap(),
            client,
        }
    }

    pub fn fetch(&self, col_uid: &str, options: Option<&FetchOptions>) -> Result<EncryptedCollection> {
        let url = apply_fetch_options(self.api_base.join(&format!("{}/", col_uid))?, options);
        let res = self.client.get(&url)?
            .send()?;
        let res = res.error_for_status()?.bytes()?;

        let serialized: EncryptedCollection = rmp_serde::from_read_ref(&res)?;
        serialized.mark_saved();

        Ok(serialized)
    }

    pub fn list(&self, options: Option<&FetchOptions>) -> Result<ListResponse<EncryptedCollection>> {
        let url = apply_fetch_options(self.api_base.clone(), options);
        let res = self.client.get(&url)?
            .send()?;
        let res = res.error_for_status()?.bytes()?;

        let serialized: ListResponse<EncryptedCollection> = rmp_serde::from_read_ref(&res)?;
        serialized.data.iter().for_each(|x| x.mark_saved());

        let ret = ListResponse {
            data: serialized.data,
            done: serialized.done,
        };

        Ok(ret)
    }

    pub fn create(&self, collection: &EncryptedCollection, options: Option<&FetchOptions>) -> Result<()> {
        let url = apply_fetch_options(self.api_base.clone(), options);
        let body = rmp_serde::to_vec_named(&collection)?;

        let res = self.client.post(&url)?
            .body(body)
            .send()?;
        res.error_for_status()?.bytes()?;

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
    client: Rc<Client>,
}

impl ItemManagerOnline {
    pub fn new(client: Rc<Client>, col: &EncryptedCollection) -> Self {
        Self {
            api_base: client.api_base.join(&format!("api/v1/collection/{}/item/", col.get_uid())).unwrap(),
            client,
        }
    }

    pub fn fetch(&self, item_uid: &str, options: Option<&FetchOptions>) -> Result<EncryptedItem> {
        let url = apply_fetch_options(self.api_base.join(&format!("{}/", item_uid))?, options);
        let res = self.client.get(&url)?
            .send()?;
        let res = res.error_for_status()?.bytes()?;

        let serialized: EncryptedItem = rmp_serde::from_read_ref(&res)?;
        serialized.mark_saved();

        Ok(serialized)
    }

    pub fn list(&self, options: Option<&FetchOptions>) -> Result<ListResponse<EncryptedItem>> {
        let url = apply_fetch_options(self.api_base.clone(), options);
        let res = self.client.get(&url)?
            .send()?;
        let res = res.error_for_status()?.bytes()?;

        let serialized: ListResponse<EncryptedItem> = rmp_serde::from_read_ref(&res)?;
        serialized.data.iter().for_each(|x| x.mark_saved());

        let ret = ListResponse {
            data: serialized.data,
            done: serialized.done,
        };

        Ok(ret)
    }

    pub fn fetch_updates<'a, I>(&self, items: I, options: Option<&FetchOptions>) -> Result<ListResponse<EncryptedItem>>
        where I: Iterator<Item = &'a EncryptedItem>
        {

        let want_etag = options.and_then(|x| x.stoken).is_none();
        let items: Vec<ItemBatchBodyDep> = items.map(|x| {
            ItemBatchBodyDep {
                uid: x.get_uid(),
                etag: if want_etag {
                    x.get_etag()
                } else {
                    None
                }
            }
        }).collect();

        let body = rmp_serde::to_vec_named(&items)?;
        let url = apply_fetch_options(self.api_base.join("fetch_updates/")?, options);
        let res = self.client.post(&url)?
            .body(body)
            .send()?;
        let res = res.error_for_status()?.bytes()?;

        let serialized: ListResponse<EncryptedItem> = rmp_serde::from_read_ref(&res)?;
        serialized.data.iter().for_each(|x| x.mark_saved());

        let ret = ListResponse {
            data: serialized.data,
            done: serialized.done,
        };

        Ok(ret)
    }

    pub fn batch<'a, I, J>(&self, items: I, deps: J, options: Option<&FetchOptions>) -> Result<()>
        where I: Iterator<Item = &'a EncryptedItem>, J: Iterator<Item = &'a EncryptedItem>
        {

        let url = apply_fetch_options(self.api_base.join("batch/")?, options);

        let items: Vec<&EncryptedItem> = items.collect();
        let deps: Vec<ItemBatchBodyDep> = deps.map(|x| {
            ItemBatchBodyDep {
                uid: x.get_uid(),
                etag: x.get_etag(),
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

        let res = self.client.post(&url)?
            .body(body)
            .send()?;
        res.error_for_status()?.bytes()?;

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
                uid: x.get_uid(),
                etag: x.get_etag(),
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

        let res = self.client.post(&url)?
            .body(body)
            .send()?;
        res.error_for_status()?;

        for item in items {
            item.mark_saved();
        }

        Ok(())
    }
}
