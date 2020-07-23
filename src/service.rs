// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate rmp_serde;

use std::rc::Rc;
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
        StrBase64,
        randombytes,
        SYMMETRIC_KEY_SIZE,
    },
    encrypted_models::{
        AccountCryptoManager,
        CollectionCryptoManager,
        ItemCryptoManager,
        Etag,
        EncryptedCollection,
        EncryptedItem,
        CollectionMetadata,
        ItemMetadata,
    },
    online_managers::{
        Authenticator,
        Client,
        User,
        LoginResponseUser,
        LoginBodyResponse,
        CollectionManagerOnline,
        ItemManagerOnline,
        ListResponse,
        FetchOptions,
    },
};

struct MainCryptoManager(CryptoManager);

impl MainCryptoManager {
    pub fn new(key: &[u8; 32], version: u8) -> Result<MainCryptoManager> {
        let context = b"Main    ";

        Ok(MainCryptoManager {
            0: CryptoManager::new(key, &context, version)?,
        })
    }

    pub fn get_login_crypto_manager(&self) -> Result<LoginCryptoManager> {
        LoginCryptoManager::keygen(&self.0.asym_key_seed)
    }

    pub fn get_account_crypto_manager(&self, key: &[u8; 32]) -> Result<AccountCryptoManager> {
        AccountCryptoManager::new(key, self.0.version)
    }
}

struct StorageCryptoManager(CryptoManager);

impl StorageCryptoManager {
    pub fn new(key: &[u8; 32], version: u8) -> Result<Self> {
        let context = b"Stor    ";

        Ok(Self {
            0: CryptoManager::new(key, &context, version)?,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountData<'a> {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub key: &'a [u8],
    pub user: LoginResponseUser,
    pub server_url: &'a str,
    pub auth_token: Option<&'a str>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDataStored<'a> {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub encrypted_data: &'a [u8],
}

pub struct Account {
    main_key: Vec<u8>,
    version: u8,
    pub user: LoginResponseUser,
    client: Rc<Client>,
    account_crypto_manager: Rc<AccountCryptoManager>,
}

impl Account {
    pub fn signup(mut client: Client, user: &User, password: &str) -> Result<Self> {
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
        let encrypted_content = main_crypto_manager.0.encrypt(&content, None)?;

        let login_response = authenticator.signup(user, &salt, &login_crypto_manager.get_pubkey(),
                                                  &identity_crypto_manager.get_pubkey(), &encrypted_content)?;

        client.set_token(Some(&login_response.token));

        let account_crypto_manager = main_crypto_manager.get_account_crypto_manager(try_into!(&account_key[..])?)?;

        let ret = Self {
            main_key,
            version,
            user: login_response.user,
            client: Rc::new(client),
            account_crypto_manager: Rc::new(account_crypto_manager),
        };

        Ok(ret)
    }

    pub fn login(mut client: Client, username: &str, password: &str) -> Result<Self> {
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

        client.set_token(Some(&login_response.token));

        let content = main_crypto_manager.0.decrypt(&login_response.user.encrypted_content, None)?;
        let account_key = &content[..SYMMETRIC_KEY_SIZE];
        let account_crypto_manager = main_crypto_manager.get_account_crypto_manager(try_into!(&account_key[..])?)?;

        let ret = Self {
            main_key,
            version,
            user: login_response.user,
            client: Rc::new(client),
            account_crypto_manager: Rc::new(account_crypto_manager),
        };

        Ok(ret)
    }

    pub fn fetch_token(&mut self) -> Result<()> {
        let mut client = (*self.client).clone();
        client.set_token(None);
        let authenticator = Authenticator::new(&client);
        let login_challenge = authenticator.get_login_challenge(&self.user.username)?;

        let version = self.version;

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

        client.set_token(Some(&login_response.token));
        self.client = Rc::new(client);

        Ok(())
    }

    pub fn force_api_base(&mut self, api_base: &str) -> Result<()> {
        let mut client = (*self.client).clone();
        client.set_api_base(api_base)?;
        self.client = Rc::new(client);

        Ok(())
    }

    pub fn change_password(&mut self, password: &str) -> Result<()> {
        let authenticator = Authenticator::new(&self.client);
        let version = self.version;
        let username = &self.user.username;
        let main_key = &self.main_key;
        let login_challenge = authenticator.get_login_challenge(username)?;

        let old_main_crypto_manager = MainCryptoManager::new(try_into!(&main_key[..])?, version)?;
        let content = old_main_crypto_manager.0.decrypt(&self.user.encrypted_content, None)?;
        let old_login_crypto_manager = old_main_crypto_manager.get_login_crypto_manager()?;

        let main_key = derive_key(&login_challenge.salt, &password)?;
        let main_crypto_manager = MainCryptoManager::new(try_into!(&main_key[..])?, version)?;
        let login_crypto_manager = main_crypto_manager.get_login_crypto_manager()?;

        let encrypted_content = main_crypto_manager.0.encrypt(&content, None)?;


        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct Body<'a> {
            pub username: &'a str,
            #[serde(with = "serde_bytes")]
            pub challenge: &'a [u8],
            pub host: &'a str,
            pub action: &'a str,

            #[serde(with = "serde_bytes")]
            pub login_pubkey: &'a [u8],
            #[serde(with = "serde_bytes")]
            pub encrypted_content: &'a [u8],
        }

        let response_struct = Body {
            username,
            challenge: &login_challenge.challenge,
            host: &self.client.get_api_base().host_str().unwrap_or(&self.client.get_api_base().as_str()),
            action: "changePassword",

            login_pubkey: &login_crypto_manager.get_pubkey(),
            encrypted_content: &encrypted_content,
        };
        let response = rmp_serde::to_vec_named(&response_struct)?;

        let signature = old_login_crypto_manager.sign_detached(&response)?;

        authenticator.change_password(&response, &signature)?;

        self.main_key = main_key;
        self.user.encrypted_content = encrypted_content;
        Ok(())
    }

    pub fn logout(self) -> Result<()> {
        let authenticator = Authenticator::new(&self.client);

        authenticator.logout()
    }

    pub fn save(&self, encryption_key: Option<&[u8]>) -> Result<String> {
        let version = super::CURRENT_VERSION;
        let encryption_key = encryption_key.unwrap_or(&[0; 32]);
        let crypto_manager = StorageCryptoManager::new(try_into!(encryption_key)?, version)?;
        let account_data = AccountData {
            user: self.user.clone(),
            version,
            key: &crypto_manager.0.encrypt(&self.main_key, None)?,
            auth_token: self.client.get_token(),
            server_url: self.client.get_api_base().as_str(),
        };
        let serialized = rmp_serde::to_vec_named(&account_data)?;

        let ret = AccountDataStored {
            version,
            encrypted_data: &crypto_manager.0.encrypt(&serialized, Some(&[version]))?,
        };
        let serialized = rmp_serde::to_vec_named(&ret)?;

        to_base64(&serialized)
    }

    pub fn restore(mut client: Client, account_data_stored: &str, encryption_key: Option<&[u8]>) -> Result<Self> {
        let encryption_key = encryption_key.unwrap_or(&[0; 32]);
        let account_data_stored = from_base64(account_data_stored)?;
        let account_data_stored: AccountDataStored = rmp_serde::from_read_ref(&account_data_stored)?;
        let version = account_data_stored.version;

        let crypto_manager = StorageCryptoManager::new(try_into!(encryption_key)?, version)?;
        let decrypted = crypto_manager.0.decrypt(&account_data_stored.encrypted_data, Some(&[version]))?;
        let account_data: AccountData = rmp_serde::from_read_ref(&decrypted)?;

        client.set_token(account_data.auth_token);
        client.set_api_base(account_data.server_url)?;

        let main_key = crypto_manager.0.decrypt(account_data.key, None)?;

        let main_crypto_manager = MainCryptoManager::new(try_into!(&main_key[..])?, version)?;
        let content = main_crypto_manager.0.decrypt(&account_data.user.encrypted_content, None)?;
        let account_key = &content[..SYMMETRIC_KEY_SIZE];
        let account_crypto_manager = main_crypto_manager.get_account_crypto_manager(try_into!(&account_key[..])?)?;

        Ok(Self {
            user: account_data.user,
            version: account_data.version,
            main_key,
            client: Rc::new(client),
            account_crypto_manager: Rc::new(account_crypto_manager),
        })
    }

    pub fn get_collection_manager(&self) -> Result<CollectionManager> {
        CollectionManager::new(Rc::clone(&self.client), Rc::clone(&self.account_crypto_manager))
    }
}

pub struct CollectionManager {
    account_crypto_manager: Rc<AccountCryptoManager>,
    client: Rc<Client>,
    collection_manager_online: CollectionManagerOnline,
}

impl CollectionManager {
    fn new(client: Rc<Client>, account_crypto_manager: Rc<AccountCryptoManager>) -> Result<Self> {
        let collection_manager_online = CollectionManagerOnline::new(Rc::clone(&client));
        Ok(Self {
            account_crypto_manager,
            client,
            collection_manager_online,
        })
    }

    pub fn create(&self, meta: &CollectionMetadata, content: &[u8]) -> Result<Collection> {
        let encrypted_collection = EncryptedCollection::new(&self.account_crypto_manager, meta, content)?;
        Collection::new(encrypted_collection.get_crypto_manager(&self.account_crypto_manager)?, encrypted_collection)
    }

    pub fn fetch(&self, col_uid: &StrBase64, options: Option<&FetchOptions>) -> Result<Collection> {
        let encrypted_collection = self.collection_manager_online.fetch(&col_uid, options)?;
        Collection::new(encrypted_collection.get_crypto_manager(&self.account_crypto_manager)?, encrypted_collection)
    }

    pub fn list(&self, options: Option<&FetchOptions>) -> Result<ListResponse<Collection>> {
        let response = self.collection_manager_online.list(options)?;

        let data: Result<Vec<Collection>> = response.data.into_iter().map(|x| Collection::new(x.get_crypto_manager(&self.account_crypto_manager)?, x)).collect();
        Ok(ListResponse {
            data: data?,
            done: response.done,
        })
    }

    pub fn upload(&self, collection: &Collection, options: Option<&FetchOptions>) -> Result<()> {
        let col = &collection.col;
        match col.get_etag() {
            Some(_) => {
                let item_manager_online = ItemManagerOnline::new(Rc::clone(&self.client), &col);
                item_manager_online.batch(vec![col.get_item()].into_iter(), vec![].into_iter(), options)?;
            },
            None => {
                self.collection_manager_online.create(&col, options)?;
            },
        };

        Ok(())
    }

    pub fn transaction(&self, collection: &Collection, options: Option<&FetchOptions>) -> Result<()> {
        let col = &collection.col;
        match col.get_etag() {
            Some(_) => {
                let item_manager_online = ItemManagerOnline::new(Rc::clone(&self.client), &col);
                item_manager_online.transaction(vec![col.get_item()].into_iter(), vec![].into_iter(), options)?;
            },
            None => {
                self.collection_manager_online.create(&col, options)?;
            },
        };

        Ok(())
    }

    pub fn get_item_manager(&self, collection: &Collection) -> Result<ItemManager> {
        ItemManager::new(Rc::clone(&self.client), Rc::clone(&collection.cm), collection)
    }
}

pub struct ItemManager {
    collection_crypto_manager: Rc<CollectionCryptoManager>,
    item_manager_online: ItemManagerOnline,
}

impl ItemManager {
    fn new(client: Rc<Client>, collection_crypto_manager: Rc<CollectionCryptoManager>, collection: &Collection) -> Result<Self> {
        let item_manager_online = ItemManagerOnline::new(Rc::clone(&client), &collection.col);
        Ok(Self {
            collection_crypto_manager,
            item_manager_online,
        })
    }

    pub fn create(&self, meta: &ItemMetadata, content: &[u8]) -> Result<Item> {
        let encrypted_item = EncryptedItem::new(&self.collection_crypto_manager, meta, content)?;
        Item::new(encrypted_item.get_crypto_manager(&self.collection_crypto_manager)?, encrypted_item)
    }

    pub fn fetch(&self, item_uid: &StrBase64, options: Option<&FetchOptions>) -> Result<Item> {
        let encrypted_item = self.item_manager_online.fetch(&item_uid, options)?;
        Item::new(encrypted_item.get_crypto_manager(&self.collection_crypto_manager)?, encrypted_item)
    }

    pub fn list(&self, options: Option<&FetchOptions>) -> Result<ListResponse<Item>> {
        let response = self.item_manager_online.list(options)?;

        let data: Result<Vec<Item>> = response.data.into_iter().map(|x| Item::new(x.get_crypto_manager(&self.collection_crypto_manager)?, x)).collect();
        Ok(ListResponse {
            data: data?,
            done: response.done,
        })
    }

    pub fn batch<'a, I>(&self, items: I, options: Option<&FetchOptions>) -> Result<()>
        where I: Iterator<Item = &'a Item>
        {

        let items = items.map(|x| &x.item);
        let deps = vec![].into_iter();
        self.item_manager_online.batch(items, deps, options)
    }

    pub fn batch_deps<'a, I, J>(&self, items: I, deps: J, options: Option<&FetchOptions>) -> Result<()>
        where I: Iterator<Item = &'a Item>, J: Iterator<Item = &'a Item>
        {

        let items = items.map(|x| &x.item);
        let deps = deps.map(|x| &x.item);
        self.item_manager_online.batch(items, deps, options)
    }

    pub fn transaction<'a, I>(&self, items: I, options: Option<&FetchOptions>) -> Result<()>
        where I: Iterator<Item = &'a Item>
        {

        let items = items.map(|x| &x.item);
        let deps = vec![].into_iter();
        self.item_manager_online.transaction(items, deps, options)
    }

    pub fn transaction_deps<'a, I, J>(&self, items: I, deps: J, options: Option<&FetchOptions>) -> Result<()>
        where I: Iterator<Item = &'a Item>, J: Iterator<Item = &'a Item>
        {

        let items = items.map(|x| &x.item);
        let deps = deps.map(|x| &x.item);
        self.item_manager_online.transaction(items, deps, options)
    }
}

pub struct Collection {
    col: EncryptedCollection,
    cm: Rc<CollectionCryptoManager>,
}

impl Collection {
    fn new(crypto_manager: CollectionCryptoManager, encrypted_collection: EncryptedCollection) -> Result<Self> {
        Ok(Self {
            col: encrypted_collection,
            cm: Rc::new(crypto_manager),
        })
    }

    pub fn verify(&self) -> Result<bool> {
        self.col.verify(&self.cm)
    }

    pub fn set_meta(&mut self, meta: &CollectionMetadata) -> Result<()> {
        self.col.set_meta(&self.cm, meta)
    }

    pub fn decrypt_meta(&self) -> Result<CollectionMetadata> {
        self.col.decrypt_meta(&self.cm)
    }

    pub fn set_content(&mut self, content: &[u8]) -> Result<()> {
        self.col.set_content(&self.cm, content)
    }

    pub fn decrypt_content(&self) -> Result<Vec<u8>> {
        self.col.decrypt_content(&self.cm)
    }

    pub fn delete(&mut self) -> Result<()> {
        self.col.delete(&self.cm)
    }

    pub fn is_deleted(&self) -> bool {
        self.col.is_deleted()
    }

    pub fn get_uid(&self) -> &str {
        self.col.get_uid()
    }

    pub fn get_etag(&self) -> Etag {
        self.col.get_etag()
    }

    pub fn get_stoken(&self) -> Option<&str> {
        self.col.get_stoken()
    }
}

pub struct Item {
    item: EncryptedItem,
    cm: ItemCryptoManager,
}

impl Item {
    fn new(crypto_manager: ItemCryptoManager, encrypted_item: EncryptedItem) -> Result<Self> {
        Ok(Self {
            item: encrypted_item,
            cm: crypto_manager,
        })
    }

    pub fn verify(&self) -> Result<bool> {
        self.item.verify(&self.cm)
    }
    pub fn set_meta(&mut self, meta: &ItemMetadata) -> Result<()> {
        self.item.set_meta(&self.cm, meta)
    }

    pub fn decrypt_meta(&self) -> Result<ItemMetadata> {
        self.item.decrypt_meta(&self.cm)
    }

    pub fn set_content(&mut self, content: &[u8]) -> Result<()> {
        self.item.set_content(&self.cm, content)
    }

    pub fn decrypt_content(&self) -> Result<Vec<u8>> {
        self.item.decrypt_content(&self.cm)
    }

    pub fn delete(&mut self) -> Result<()> {
        self.item.delete(&self.cm)
    }

    pub fn is_deleted(&self) -> bool {
        self.item.is_deleted()
    }

    pub fn get_uid(&self) -> &str {
        self.item.get_uid()
    }

    pub fn get_etag(&self) -> Etag {
        self.item.get_etag()
    }
}

pub(crate) fn test_get_chunk_uids(item: &Item) -> Vec<String> {
    item.item.test_get_chunk_uids()
}
