extern crate serde_json;
extern crate hex;

use url::{Url, ParseError};

use serde::{Serialize, Deserialize};

use reqwest::{
    blocking::Client,
    header,
};

use super::{
    crypto::{
        memcmp,
        CryptoManager,
        AsymmetricKeyPair,
        AsymmetricCryptoManager,
    },
    content::{
        CollectionInfo,
        SyncEntry,
    },
};

static APP_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
);

pub static SERVICE_API_URL: &str = "https://api.etesync.com";

const HMAC_SIZE: usize = 32;

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
#[serde(rename_all = "camelCase")]
struct JournalJson {
    uid: String,
    version: u8,
    owner: String,
    content: String,
    read_only: Option<bool>,
    key: Option<String>,
    last_uid: Option<String>,
}

#[derive(Clone)]
pub struct Journal {
    pub uid: String,
    pub version: u8,
    pub owner: String,
    pub content: Vec<u8>,
    pub key: Option<Vec<u8>>,

    read_only: bool,
    last_uid: Option<String>,
}

impl Journal {
    pub fn new(uid: &str, version: u8, owner: &str) -> Journal {
        Journal {
            uid: uid.to_owned(),
            version,
            owner: owner.to_owned(),
            content: vec![],
            key: None,

            read_only: false,
            last_uid: None,
        }
    }

    // FIXME: this should return a result
    fn from_json(uid: &str, json: &JournalJson) -> Journal {
        Journal {
            uid: uid.to_owned(),
            version: json.version,
            owner: json.owner.clone(),
            read_only: match json.read_only {
                Some(val) => val,
                None => false,
            },
            content: base64::decode(&json.content).unwrap(),
            key: match &json.key {
                Some(val) => Some(base64::decode(val).unwrap()),
                None => None,
            },
            last_uid: json.last_uid.clone(),
        }
    }

    fn to_json(&self) -> JournalJson {
        JournalJson {
            uid: self.uid.clone(),
            version: self.version,
            owner: self.owner.clone(),
            read_only: Some(self.read_only),
            content: base64::encode(&self.content),
            key: match &self.key {
                Some(val) => Some(base64::encode(val)),
                None => None,
            },
            last_uid: None,
        }
    }

    pub fn is_read_only(&self) -> bool {
        return self.read_only;
    }

    pub fn get_last_uid(&self) -> &Option<String> {
        return &self.last_uid;
    }

    pub fn get_crypto_manager(&self, key: &[u8], keypair: &AsymmetricKeyPair) -> Result<CryptoManager, &'static str> {
        if let Some(key) = &self.key {
            let asymmetric_crypto_manager = AsymmetricCryptoManager::new(&keypair);
            let derived = asymmetric_crypto_manager.decrypt(&key).unwrap();

            return CryptoManager::from_derived_key(&derived, self.version);
        } else {
            return CryptoManager::new(key, &self.uid, self.version);
        }
    }

    pub fn set_info(&mut self, crypto_manager: &CryptoManager, info: &CollectionInfo) -> Result<(), &'static str> {
        let json = serde_json::to_vec(&info).unwrap();
        let ciphertext = crypto_manager.encrypt(&json)?;
        let hmac = self.calculate_hmac(crypto_manager, &ciphertext)?;
        let mut content = hmac;
        content.extend(ciphertext);
        self.content = content;

        Ok(())
    }

    pub fn get_info(&self, crypto_manager: &CryptoManager) -> Result<CollectionInfo, Box<dyn std::error::Error>> {
        self.verify(&crypto_manager)?;

        let ciphertext = &self.content[HMAC_SIZE..];
        let info = crypto_manager.decrypt(ciphertext)?;
        let info = serde_json::from_slice(&info)?;

        Ok(info)
    }

    fn calculate_hmac(&self, crypto_manager: &CryptoManager, message: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut data = self.uid.as_bytes().to_vec();
        data.extend(message);
        let hmac = crypto_manager.hmac(&data)?;

        Ok(hmac)
    }

    fn verify(&self, crypto_manager: &CryptoManager) -> Result<(), &'static str> {
        let hmac = &self.content[..HMAC_SIZE];
        let ciphertext = &self.content[HMAC_SIZE..];
        let calculated = self.calculate_hmac(crypto_manager, &ciphertext)?;

        if memcmp(&hmac, &calculated) {
            return Ok(());
        } else {
            return Err("HMAC mismatch");
        }
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

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct EntryJson {
    uid: String,
    content: String,
}

#[derive(Clone)]
pub struct Entry {
    pub uid: String,
    pub content: Vec<u8>,
}

impl Entry {
    pub fn from_sync_entry(crypto_manager: &CryptoManager, sync_entry: &SyncEntry, prev_uid: Option<& str>) -> Result<Entry, &'static str> {
        let json = serde_json::to_vec(&sync_entry).unwrap();
        let ciphertext = crypto_manager.encrypt(&json)?;
        let hmac = Entry::calculate_hmac(crypto_manager, &ciphertext, prev_uid)?;

        let ret = Entry {
            uid: hex::encode(hmac),
            content: ciphertext,
        };

        Ok(ret)
    }

    // FIXME: this should return a result
    fn from_json(uid: &str, json: &EntryJson) -> Entry {
        #[allow(non_snake_case)]
        Entry {
            uid: uid.to_owned(),
            content: base64::decode(&json.content).unwrap(),
        }
    }

    fn to_json(&self) -> EntryJson {
        EntryJson {
            uid: self.uid.clone(),
            content: base64::encode(&self.content),
        }
    }

    pub fn get_sync_entry(&self, crypto_manager: &CryptoManager, prev_uid: Option<& str>) -> Result<SyncEntry, Box<dyn std::error::Error>> {
        self.verify(&crypto_manager, prev_uid)?;

        let ciphertext = &self.content;
        let info = crypto_manager.decrypt(ciphertext)?;
        let info = serde_json::from_slice(&info)?;

        Ok(info)
    }

    fn calculate_hmac(crypto_manager: &CryptoManager, message: &[u8], prev_uid: Option<& str>) -> Result<Vec<u8>, &'static str> {
        let mut data = match prev_uid {
            Some(prev_uid) => prev_uid.as_bytes().to_vec(),
            None => vec![],
        };
        data.extend(message);
        let hmac = crypto_manager.hmac(&data)?;

        Ok(hmac)
    }

    fn verify(&self, crypto_manager: &CryptoManager, prev_uid: Option<& str>) -> Result<(), &'static str> {
        let calculated = Entry::calculate_hmac(crypto_manager, &self.content, prev_uid)?;
        let hmac = match hex::decode(&self.uid) {
            Ok(hmac) => hmac,
            Err(_e) => return Err("Failed decoding uid"),
        };

        if memcmp(&hmac, &calculated) {
            return Ok(());
        } else {
            return Err("HMAC mismatch");
        }
    }
}

pub struct EntryManager<'a> {
    api_base: Url,
    client: &'a Client,
    auth_token: String,
}

impl EntryManager<'_> {
    pub fn new<'a>(client: &'a Client, auth_token: &str, journal_uid: &str, api_base: &str) -> EntryManager<'a> {
        let api_base = Url::parse(api_base).unwrap();
        let api_base = api_base.join(&format!("api/v1/journals/{}/entries/", &journal_uid)).unwrap();
        EntryManager {
            api_base,
            client,
            auth_token: auth_token.to_owned(),
        }
    }

    pub fn list(&self, last_uid: Option<&str>, limit: Option<usize>) -> Result<Vec<Entry>, Box<dyn std::error::Error>> {
        let mut url = self.api_base.clone();

        if let Some(last_uid) = last_uid {
            let mut query = url.query_pairs_mut();
            query.append_pair("last", &last_uid);
        }
        if let Some(limit) = limit {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &limit.to_string());
        }

        let headers = get_base_headers(&self.auth_token, 0);
        let res = self.client.get(url.as_str())
            .headers(headers)
            .send()?;

        match res.error_for_status() {
            Ok(res) => {
                let entrys_json = res.json::<Vec<EntryJson>>()?;
                Ok(entrys_json.into_iter().map(|entry_json| Entry::from_json(&entry_json.uid, &entry_json)).collect())
            },
            Err(err) => {
                Err(Box::new(err))
            }
        }
    }

    pub fn create(&self, entries: &[&Entry], last_uid: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
        let mut url = self.api_base.clone();

        if let Some(last_uid) = last_uid {
            let mut query = url.query_pairs_mut();
            query.append_pair("last", &last_uid);
        }
        let headers = get_base_headers(&self.auth_token, 0);

        let entries_json: Vec<EntryJson> = entries.into_iter().map(|entry| entry.to_json()).collect();

        let res = self.client.post(url.as_str())
            .headers(headers)
            .json(&entries_json)
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
