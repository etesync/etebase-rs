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

pub fn test_reset(client: &Client, body_struct: SignupBody) -> Result<()> {
    let body = rmp_serde::to_vec_named(&body_struct)?;
    let url = client.api_base.join("api/v1/test/authentication/reset/")?;

    let res = client.post(url.as_str())?
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
    pub fn new(client_name: &str, server_url: &str) -> Result<Client> {
        let req_client = ReqwestClient::builder()
            .user_agent(format!("{} {}", client_name, APP_USER_AGENT))
            .build()?;

        Ok(Client {
            req_client,
            api_base: Url::parse(server_url)?,
            auth_token: None,
        })
    }

    pub fn set_token(&mut self, token: Option<&str>) {
        self.auth_token = token.and_then(|x| Some(x.to_string()));
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
pub struct LoginChallange {
    #[serde(with = "serde_bytes")]
    pub challenge: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    pub version: u8,
}

#[derive(Serialize)]
#[allow(non_snake_case)]
pub struct SignupBody<'a> {
    pub user: &'a User<'a>,
    #[serde(with = "serde_bytes")]
    pub salt: &'a[u8],
    #[serde(with = "serde_bytes")]
    pub loginPubkey: &'a[u8],
    #[serde(with = "serde_bytes")]
    pub pubkey: &'a[u8],
    #[serde(with = "serde_bytes")]
    pub encryptedContent: &'a[u8],
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

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct LoginResponseUser {
    pub username: String,
    pub email: String,
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub encryptedContent: Vec<u8>,
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
    api_base: &'static str,
    client: &'a Client,
}

impl<'a> Authenticator<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self {
            api_base: "api/v1/authentication/",
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

        let url = [self.api_base, "login_challenge/"].concat();
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
            loginPubkey: login_pubkey,
            pubkey,
            encryptedContent: encrypted_content,
        };
        let body = rmp_serde::to_vec_named(&body_struct)?;

        let url = [self.api_base, "signup/"].concat();
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

        let url = [self.api_base, "login/"].concat();
        let res = self.client.post(&url)?
            .body(body)
            .send()?;
        let res = res.error_for_status()?.bytes()?;

        let ret: LoginResponse = rmp_serde::from_read_ref(&res)?;

        Ok(ret)
    }

    pub fn logout(&self) -> Result<()> {
        let url = [self.api_base, "logout/"].concat();
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

        let url = [self.api_base, "change_password/"].concat();
        let res = self.client.post(&url)?
            .body(body)
            .send()?;
        res.error_for_status()?;

        Ok(())
    }
}
