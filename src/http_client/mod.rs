use reqwest::{
    blocking:: {
        Client as ReqwestClient,
        RequestBuilder,
    },
    header,
};

use url::Url;

use super::error::Result;

static APP_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
);

#[derive(Clone)]
pub struct Client {
    req_client: ReqwestClient,
    auth_token: Option<String>,
    pub(crate) api_base: Url,
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

    pub fn token<'a>(&'a self) -> Option<&'a str> {
        self.auth_token.as_deref().and_then(|x| Some(&x[..]))
    }

    pub fn set_api_base(&mut self, server_url: &str) -> Result<()> {
        self.api_base = Url::parse(server_url)?;

        Ok(())
    }

    pub fn api_base(&self) -> &Url {
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

    pub fn patch(&self, url: &Url) -> Result<RequestBuilder> {
        Ok(self.prep_client(self.req_client.patch(url.as_str())))
    }

    pub fn delete(&self, url: &Url) -> Result<RequestBuilder> {
        Ok(self.prep_client(self.req_client.delete(url.as_str())))
    }
}

