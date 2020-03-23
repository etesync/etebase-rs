use url::{Url, ParseError};

use serde::Deserialize;

use reqwest::{
    blocking::Client,
    header,
};

static APP_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
);

pub static SERVICE_API_URL: &str = "https://api.etesync.com";

pub fn get_client() -> Result<Client, Box<dyn std::error::Error>> {
    let client = Client::builder()
        .user_agent(APP_USER_AGENT)
        .build()?;

    Ok(client)
}

pub struct Authenticator<'a> {
    api_base: Url,
    client: &'a Client,
}

impl Authenticator<'_> {
    pub fn new<'a>(client: &'a Client, api_base: &str) -> Authenticator<'a> {
        Authenticator {
            api_base: Url::parse(api_base).unwrap(),
            client,
        }
    }

    pub fn get_token(&self, username: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        let url = self.api_base.join("api-token-auth/")?;
        let params = [("username", username), ("password", password)];
        let res = self.client.post(url.as_str())
            .form(&params)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded;charset=UTF-8")
            .header(header::ACCEPT, "application/json")
            .send()?;

        #[derive(Deserialize)]
        struct TokenResponse {
            token: String,
        }

        let json = res.json::<TokenResponse>()?;

        Ok(json.token)
    }

    pub fn invalidate_token(&self, auth_token: &str) -> Result<String, Box<dyn std::error::Error>> {
        let url = self.api_base.join("api/logout/")?;
        let res = self.client.post(url.as_str())
            .header(header::AUTHORIZATION, format!("Token {}", auth_token))
            .send()?;

        Ok(res.text()?)
    }
}
