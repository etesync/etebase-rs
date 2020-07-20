// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate rmp_serde;

use std::convert::TryInto;

use serde::{Serialize, Deserialize};

use super::{
    try_into,
    crypto::{
        derive_key,
        CryptoManager,
        BoxCryptoManager,
        LoginCryptoManager,
    },
    error::{
        Error,
        Result,
    },
    utils::{
        from_base64,
        to_base64,
        randombytes,
        SYMMETRIC_KEY_SIZE,
    },
    online_managers::{
        Authenticator,
        Client,
        User,
        LoginResponseUser,
        LoginBodyResponse,
    },
};

struct MainCryptoManager {
    pub manager: CryptoManager,
}

impl MainCryptoManager {
    pub fn new(key: &[u8; 32], version: u8) -> Result<MainCryptoManager> {
        let context = b"Main    ";

        Ok(MainCryptoManager {
            manager: CryptoManager::new(key, &context, version)?,
        })
    }

    pub fn get_login_crypto_manager(&self) -> Result<LoginCryptoManager> {
        LoginCryptoManager::keygen(&self.manager.asym_key_seed)
    }
}

struct StorageCryptoManager {
    pub manager: CryptoManager,
}

impl StorageCryptoManager {
    pub fn new(key: &[u8; 32], version: u8) -> Result<Self> {
        let context = b"Stor    ";

        Ok(Self {
            manager: CryptoManager::new(key, &context, version)?,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct AccountData<'a> {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub key: &'a [u8],
    pub user: LoginResponseUser,
    pub serverUrl: &'a str,
    pub authToken: Option<&'a str>,
}

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct AccountDataStored<'a> {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub encryptedData: &'a [u8],
}

pub struct Account {
    main_key: Vec<u8>,
    version: u8,
    pub user: LoginResponseUser,
    client: Client,
}

impl Account {
    pub fn signup(client: Client, user: &User, password: &str) -> Result<Account> {
        super::init()?;

        let authenticator = Authenticator::new(&client);
        let version = super::CURRENT_VERSION;
        let salt = randombytes(32);

        let main_key = derive_key(&salt, &password)?;
        let main_crypto_manager = MainCryptoManager::new(try_into!(&main_key[..])?, version)?;
        let login_crypto_manager = main_crypto_manager.get_login_crypto_manager()?;

        let identity_crypto_manager = BoxCryptoManager::keygen(None)?;

        let account_key = randombytes(SYMMETRIC_KEY_SIZE);
        let content = [&account_key, &identity_crypto_manager.get_privkey()[..]].concat();
        let encrypted_content = main_crypto_manager.manager.encrypt(&content, None)?;

        let login_response = authenticator.signup(user, &salt, &login_crypto_manager.get_pubkey(),
                                                  &identity_crypto_manager.get_pubkey(), &encrypted_content)?;

        let mut client = client.clone();
        client.set_token(Some(&login_response.token));

        let ret = Account {
            main_key,
            version,
            user: login_response.user,
            client,
        };

        Ok(ret)
    }

    pub fn login(client: Client, username: &str, password: &str) -> Result<Account> {
        super::init()?;

        let authenticator = Authenticator::new(&client);
        let login_challenge = authenticator.get_login_challenge(username)?;

        let version = login_challenge.version;

        let main_key = derive_key(&login_challenge.salt, &password)?;
        let main_crypto_manager = MainCryptoManager::new(try_into!(&main_key[..])?, version)?;
        let login_crypto_manager = main_crypto_manager.get_login_crypto_manager()?;

        let response_struct = LoginBodyResponse {
            username,
            challenge: &login_challenge.challenge,
            host: client.get_api_base().host_str().unwrap_or(client.get_api_base().as_str()),
            action: "login",
        };
        let response = rmp_serde::to_vec_named(&response_struct)?;

        let signature = login_crypto_manager.sign_detached(&response)?;

        let login_response = authenticator.login(&response, &signature)?;

        let mut client = client.clone();
        client.set_token(Some(&login_response.token));

        let ret = Account {
            main_key,
            version,
            user: login_response.user,
            client,
        };

        Ok(ret)
    }

    pub fn fetch_token(&mut self) -> Result<()> {
        let authenticator = Authenticator::new(&self.client);
        let login_challenge = authenticator.get_login_challenge(&self.user.username)?;

        let version = login_challenge.version;

        let username = &self.user.username;
        let main_key = &self.main_key;
        let main_crypto_manager = MainCryptoManager::new(try_into!(&main_key[..])?, version)?;
        let login_crypto_manager = main_crypto_manager.get_login_crypto_manager()?;

        let response_struct = LoginBodyResponse {
            username,
            challenge: &login_challenge.challenge,
            host: &self.client.get_api_base().host_str().unwrap_or(&self.client.get_api_base().as_str()),
            action: "login",
        };
        let response = rmp_serde::to_vec_named(&response_struct)?;

        let signature = login_crypto_manager.sign_detached(&response)?;

        let login_response = authenticator.login(&response, &signature)?;

        self.client.set_token(Some(&login_response.token));

        Ok(())
    }

    pub fn save(&self, encryption_key: Option<&[u8]>) -> Result<String> {
        let version = super::CURRENT_VERSION;
        let encryption_key = encryption_key.unwrap_or(&[0; 32]);
        let crypto_manager = StorageCryptoManager::new(try_into!(encryption_key)?, version)?;
        let account_data = AccountData {
            user: self.user.clone(),
            version,
            key: &crypto_manager.manager.encrypt(&self.main_key, None)?,
            authToken: self.client.get_token(),
            serverUrl: self.client.get_api_base().as_str(),
        };
        let serialized = rmp_serde::to_vec_named(&account_data)?;

        let ret = AccountDataStored {
            version,
            encryptedData: &crypto_manager.manager.encrypt(&serialized, Some(&[version]))?,
        };
        let serialized = rmp_serde::to_vec_named(&ret)?;

        to_base64(&serialized)
    }

    pub fn restore(client: Client, account_data_stored: &str, encryption_key: Option<&[u8]>) -> Result<Account> {
        let encryption_key = encryption_key.unwrap_or(&[0; 32]);
        let account_data_stored = from_base64(account_data_stored)?;
        let account_data_stored: AccountDataStored = rmp_serde::from_read_ref(&account_data_stored)?;
        let version = account_data_stored.version;

        let crypto_manager = StorageCryptoManager::new(try_into!(encryption_key)?, version)?;
        let decrypted = crypto_manager.manager.decrypt(&account_data_stored.encryptedData, Some(&[version]))?;
        let account_data: AccountData = rmp_serde::from_read_ref(&decrypted)?;

        let mut client = client;
        client.set_token(account_data.authToken);
        client.set_api_base(account_data.serverUrl)?;
        Ok(Self {
            user: account_data.user,
            version: account_data.version,
            main_key: crypto_manager.manager.decrypt(account_data.key, None)?,
            client,
        })
    }

    pub fn logout(self) -> Result<()> {
        let authenticator = Authenticator::new(&self.client);

        authenticator.logout()
    }
}
