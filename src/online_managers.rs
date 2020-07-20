// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate rmp_serde;

use url::Url;

use serde::{Serialize, Deserialize};

use reqwest::{
    blocking:: {
        Client as ReqwestClient,
        RequestBuilder,
    },
    header,
};

use super::{
    error::{
        Result,
        Error,
    }
};

static APP_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
);

pub const SERVICE_API_URL: &str = "https://api.etebase.com";

pub fn test_reset(client: &Client) -> Result<()> {
    let url = client.api_base.join("test/authentication/reset/")?;

    let res = client.post(url.as_str())?
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
    pub fn new(client_name: &str, server_url: &str, token: Option<&str>) -> Result<Client> {
        let req_client = ReqwestClient::builder()
            .user_agent(format!("{} {}", client_name, APP_USER_AGENT))
            .build()?;

        Ok(Client {
            req_client,
            api_base: Url::parse(server_url)?,
            auth_token: token.and_then(|token| Some(token.to_owned())),
        })
    }

    pub fn set_token(&mut self, token: Option<&str>) {
        self.auth_token = token.and_then(|x| Some(x.to_string()));
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

    pub fn get(&self, suffix: &str) -> Result<RequestBuilder> {
        let url = self.api_base.join(suffix)?;
        Ok(self.prep_client(self.req_client.get(url)))
    }

    pub fn post(&self, suffix: &str) -> Result<RequestBuilder> {
        let url = self.api_base.join(suffix)?;
        Ok(self.prep_client(self.req_client.post(url)))
    }

    pub fn put(&self, suffix: &str) -> Result<RequestBuilder> {
        let url = self.api_base.join(suffix)?;
        Ok(self.prep_client(self.req_client.put(url)))
    }

    pub fn delete(&self, suffix: &str) -> Result<RequestBuilder> {
        let url = self.api_base.join(suffix)?;
        Ok(self.prep_client(self.req_client.delete(url)))
    }
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct LoginChallange {
    #[serde(with = "serde_bytes")]
    pub challenge: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    pub version: u8,
}

pub struct Authenticator {
    api_base: &'static str,
    client: Client,
}

impl Authenticator {
    pub fn new(client: &Client) -> Authenticator {
        Authenticator {
            api_base: "api/v1/authentication/",
            client: client.clone(),
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

        let url = [self.api_base, "login_challenge/"].concat();
        let res = self.client.post(&url)?
            .body(body)
            .send()?;
        let res = res.error_for_status()?.bytes()?;

        let ret: LoginChallange = rmp_serde::from_read_ref(&res)?;

        Ok(ret)
    }
}
