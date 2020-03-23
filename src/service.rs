use url::{Url, ParseError};

use serde::{Serialize, Deserialize};

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

pub fn test_reset(client: &Client, auth_token: &str, api_base: &str) -> Result<(), Box<dyn std::error::Error>> {
    let api_base = Url::parse(api_base)?;
    let url = api_base.join("reset/")?;

    let res = client.post(url.as_str())
        .header(header::AUTHORIZATION, format!("Token {}", auth_token))
        .send()?;

    match res.error_for_status() {
        Ok(_res) => Ok(()),
        Err(err) => {
            Err(Box::new(err))
        }
    }
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

fn get_base_headers(auth_token: &str, capacity: usize) -> header::HeaderMap<header::HeaderValue> {
    let capacity = capacity + 3;
    let mut map = header::HeaderMap::with_capacity(capacity);
    map.insert(header::CONTENT_TYPE, "application/json;charset=UTF-8".parse().unwrap());
    map.insert(header::ACCEPT, "application/json".parse().unwrap());
    map.insert(header::AUTHORIZATION, format!("Token {}", auth_token).parse().unwrap());

    map
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct JournalJson {
    uid: String,
    version: u8,
    owner: String,
    content: String,
    readOnly: Option<bool>,
    key: Option<String>,
    lastUid: Option<String>,
}

#[derive(Clone)]
pub struct Journal {
    pub uid: String,
    pub version: u8,
    pub owner: String,
    pub content: Vec<u8>,
    pub read_only: bool,
    pub key: Option<Vec<u8>>,
    pub last_uid: Option<String>,
}

impl Journal {
    // FIXME: this should return a result
    fn from_json(uid: &str, json: &JournalJson) -> Journal {
        #[allow(non_snake_case)]
        Journal {
            uid: uid.to_owned(),
            version: json.version,
            owner: json.owner.clone(),
            read_only: match json.readOnly {
                Some(val) => val,
                None => false,
            },
            content: base64::decode(&json.content).unwrap(),
            key: match &json.key {
                Some(val) => Some(base64::decode(val).unwrap()),
                None => None,
            },
            last_uid: json.lastUid.clone(),
        }
    }

    fn to_json(&self) -> JournalJson {
        JournalJson {
            uid: self.uid.clone(),
            version: self.version,
            owner: self.owner.clone(),
            readOnly: Some(self.read_only),
            content: base64::encode(&self.content),
            key: match &self.key {
                Some(val) => Some(base64::encode(val)),
                None => None,
            },
            lastUid: None,
        }
    }

    pub fn get_crypto_manager() {
    }
}

pub struct JournalManager<'a> {
    api_base: Url,
    client: &'a Client,
    auth_token: String,
}

impl JournalManager<'_> {
    pub fn new<'a>(client: &'a Client, auth_token: &str, api_base: &str) -> JournalManager<'a> {
        let api_base = Url::parse(api_base).unwrap();
        let api_base = api_base.join("api/v1/journals/").unwrap();
        JournalManager {
            api_base,
            client,
            auth_token: auth_token.to_owned(),
        }
    }

    pub fn fetch(&self, journal_uid: &str) -> Result<Journal, Box<dyn std::error::Error>> {
        let url = self.api_base.join(&format!{"{}/", journal_uid})?;
        let headers = get_base_headers(&self.auth_token, 0);
        let res = self.client.get(url.as_str())
            .headers(headers)
            .send()?;

        match res.error_for_status() {
            Ok(res) => {
                let journal_json = res.json::<JournalJson>()?;
                Ok(Journal::from_json(journal_uid, &journal_json))
            },
            Err(err) => {
                Err(Box::new(err))
            }
        }
    }

    pub fn list(&self) -> Result<Vec<Journal>, Box<dyn std::error::Error>> {
        let url = &self.api_base;
        let headers = get_base_headers(&self.auth_token, 0);
        let res = self.client.get(url.as_str())
            .headers(headers)
            .send()?;

        match res.error_for_status() {
            Ok(res) => {
                let journals_json = res.json::<Vec<JournalJson>>()?;
                Ok(journals_json.into_iter().map(|journal_json| Journal::from_json(&journal_json.uid, &journal_json)).collect())
            },
            Err(err) => {
                Err(Box::new(err))
            }
        }
    }

    pub fn create(&self, journal: &Journal) -> Result<(), Box<dyn std::error::Error>> {
        let url = &self.api_base;
        let headers = get_base_headers(&self.auth_token, 0);

        let journal_json = journal.to_json();

        let res = self.client.post(url.as_str())
            .headers(headers)
            .json(&journal_json)
            .send()?;

        match res.error_for_status() {
            Ok(_res) => {
                Ok(())
            },
            Err(err) => {
                Err(Box::new(err))
            }
        }
    }

    pub fn update(&self, journal: &Journal) -> Result<(), Box<dyn std::error::Error>> {
        let url = self.api_base.join(&format!{"{}/", &journal.uid})?;
        let headers = get_base_headers(&self.auth_token, 0);

        let journal_json = journal.to_json();

        let res = self.client.put(url.as_str())
            .headers(headers)
            .json(&journal_json)
            .send()?;

        match res.error_for_status() {
            Ok(_res) => {
                Ok(())
            },
            Err(err) => {
                Err(Box::new(err))
            }
        }
    }

    pub fn delete(&self, journal: &Journal) -> Result<(), Box<dyn std::error::Error>> {
        let url = self.api_base.join(&format!{"{}/", &journal.uid})?;
        let headers = get_base_headers(&self.auth_token, 0);

        let res = self.client.delete(url.as_str())
            .headers(headers)
            .send()?;

        match res.error_for_status() {
            Ok(_res) => {
                Ok(())
            },
            Err(err) => {
                Err(Box::new(err))
            }
        }
    }
}
