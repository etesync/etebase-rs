// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate rmp_serde;

use std::sync::Arc;
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
        MsgPackSerilization,
    },
    encrypted_models::{
        AccountCryptoManager,
        CollectionCryptoManager,
        ItemCryptoManager,
        CollectionAccessLevel,
        EncryptedCollection,
        EncryptedItem,
        SignedInvitation,
        CollectionMetadata,
        ItemMetadata,
    },
    http_client::Client,
    online_managers::{
        Authenticator,
        User,
        UserProfile,
        LoginResponseUser,
        LoginBodyResponse,
        CollectionManagerOnline,
        ItemManagerOnline,
        CollectionMemberManagerOnline,
        CollectionMember,
        CollectionInvitationManagerOnline,
        CollectionListResponse,
        ItemListResponse,
        IteratorListResponse,
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

    pub fn login_crypto_manager(&self) -> Result<LoginCryptoManager> {
        LoginCryptoManager::keygen(&self.0.asym_key_seed)
    }

    pub fn account_crypto_manager(&self, key: &[u8; 32]) -> Result<AccountCryptoManager> {
        AccountCryptoManager::new(key, self.0.version)
    }

    pub fn identity_crypto_manager(&self, privkey: &[u8; 32]) -> Result<BoxCryptoManager> {
        BoxCryptoManager::from_privkey(privkey)
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
    client: Arc<Client>,
    account_crypto_manager: Arc<AccountCryptoManager>,
}

impl Account {
    pub fn signup(mut client: Client, user: &User, password: &str) -> Result<Self> {
        super::init()?;

        let authenticator = Authenticator::new(&client);
        let version = super::CURRENT_VERSION;
        let salt = randombytes(32);

        let main_key = derive_key(&salt, &password)?;
        let main_crypto_manager = MainCryptoManager::new(try_into!(&main_key[..])?, version)?;
        let login_crypto_manager = main_crypto_manager.login_crypto_manager()?;

        let identity_crypto_manager = BoxCryptoManager::keygen(None)?;

        let account_key = randombytes(SYMMETRIC_KEY_SIZE);
        let content = [&account_key, &identity_crypto_manager.privkey()[..]].concat();
        let encrypted_content = main_crypto_manager.0.encrypt(&content, None)?;

        let login_response = authenticator.signup(user, &salt, &login_crypto_manager.pubkey(),
                                                  &identity_crypto_manager.pubkey(), &encrypted_content)?;

        client.set_token(Some(&login_response.token));

        let account_crypto_manager = main_crypto_manager.account_crypto_manager(try_into!(&account_key[..])?)?;

        let ret = Self {
            main_key,
            version,
            user: login_response.user,
            client: Arc::new(client),
            account_crypto_manager: Arc::new(account_crypto_manager),
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
        let login_crypto_manager = main_crypto_manager.login_crypto_manager()?;

        let response_struct = LoginBodyResponse {
            username,
            challenge: &login_challenge.challenge,
            host: client.api_base().host_str().unwrap_or(client.api_base().as_str()),
            action: "login",
        };
        let response = rmp_serde::to_vec_named(&response_struct)?;

        let signature = login_crypto_manager.sign_detached(&response)?;

        let login_response = authenticator.login(&response, &signature)?;

        client.set_token(Some(&login_response.token));

        let content = main_crypto_manager.0.decrypt(&login_response.user.encrypted_content, None)?;
        let account_key = &content[..SYMMETRIC_KEY_SIZE];
        let account_crypto_manager = main_crypto_manager.account_crypto_manager(try_into!(&account_key[..])?)?;

        let ret = Self {
            main_key,
            version,
            user: login_response.user,
            client: Arc::new(client),
            account_crypto_manager: Arc::new(account_crypto_manager),
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
        let login_crypto_manager = main_crypto_manager.login_crypto_manager()?;

        let response_struct = LoginBodyResponse {
            username,
            challenge: &login_challenge.challenge,
            host: &self.client.api_base().host_str().unwrap_or(&self.client.api_base().as_str()),
            action: "login",
        };
        let response = rmp_serde::to_vec_named(&response_struct)?;

        let signature = login_crypto_manager.sign_detached(&response)?;

        let login_response = authenticator.login(&response, &signature)?;

        client.set_token(Some(&login_response.token));
        self.client = Arc::new(client);

        Ok(())
    }

    pub fn force_api_base(&mut self, api_base: &str) -> Result<()> {
        let mut client = (*self.client).clone();
        client.set_api_base(api_base)?;
        self.client = Arc::new(client);

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
        let old_login_crypto_manager = old_main_crypto_manager.login_crypto_manager()?;

        let main_key = derive_key(&login_challenge.salt, &password)?;
        let main_crypto_manager = MainCryptoManager::new(try_into!(&main_key[..])?, version)?;
        let login_crypto_manager = main_crypto_manager.login_crypto_manager()?;

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
            host: &self.client.api_base().host_str().unwrap_or(&self.client.api_base().as_str()),
            action: "changePassword",

            login_pubkey: &login_crypto_manager.pubkey(),
            encrypted_content: &encrypted_content,
        };
        let response = rmp_serde::to_vec_named(&response_struct)?;

        let signature = old_login_crypto_manager.sign_detached(&response)?;

        authenticator.change_password(&response, &signature)?;

        self.main_key = main_key;
        self.user.encrypted_content = encrypted_content;
        Ok(())
    }

    pub fn logout(&self) -> Result<()> {
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
            auth_token: self.client.token(),
            server_url: self.client.api_base().as_str(),
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
        let account_crypto_manager = main_crypto_manager.account_crypto_manager(try_into!(&account_key[..])?)?;

        Ok(Self {
            user: account_data.user,
            version: account_data.version,
            main_key,
            client: Arc::new(client),
            account_crypto_manager: Arc::new(account_crypto_manager),
        })
    }

    pub fn collection_manager(&self) -> Result<CollectionManager> {
        CollectionManager::new(Arc::clone(&self.client), Arc::clone(&self.account_crypto_manager))
    }

    pub fn invitation_manager(&self) -> Result<CollectionInvitationManager> {
        CollectionInvitationManager::new(Arc::clone(&self.client), Arc::clone(&self.account_crypto_manager), self.identity_crypto_manager()?)
    }

    fn main_crypto_manager(&self) -> Result<MainCryptoManager> {
        let version = self.version;
        let main_key = &self.main_key;
        MainCryptoManager::new(try_into!(&main_key[..])?, version)
    }

    fn identity_crypto_manager(&self) -> Result<BoxCryptoManager> {
        let main_crypto_manager = self.main_crypto_manager()?;
        let content = main_crypto_manager.0.decrypt(&self.user.encrypted_content, None)?;
        let privkey = &content[SYMMETRIC_KEY_SIZE..];
        main_crypto_manager.identity_crypto_manager(try_into!(privkey)?)
    }
}

pub struct CollectionManager {
    account_crypto_manager: Arc<AccountCryptoManager>,
    client: Arc<Client>,
    collection_manager_online: CollectionManagerOnline,
}

impl CollectionManager {
    fn new(client: Arc<Client>, account_crypto_manager: Arc<AccountCryptoManager>) -> Result<Self> {
        let collection_manager_online = CollectionManagerOnline::new(Arc::clone(&client));
        Ok(Self {
            account_crypto_manager,
            client,
            collection_manager_online,
        })
    }

    pub fn create<T: MsgPackSerilization>(&self, meta: &T, content: &[u8]) -> Result<Collection> {
        let meta = meta.to_msgpack()?;
        let encrypted_collection = EncryptedCollection::new(&self.account_crypto_manager, &meta, content)?;
        Collection::new(encrypted_collection.crypto_manager(&self.account_crypto_manager)?, encrypted_collection)
    }

    pub fn fetch(&self, col_uid: &StrBase64, options: Option<&FetchOptions>) -> Result<Collection> {
        let encrypted_collection = self.collection_manager_online.fetch(&col_uid, options)?;
        Collection::new(encrypted_collection.crypto_manager(&self.account_crypto_manager)?, encrypted_collection)
    }

    pub fn list(&self, options: Option<&FetchOptions>) -> Result<CollectionListResponse<Collection>> {
        let response = self.collection_manager_online.list(options)?;

        let data: Result<Vec<Collection>> = response.data.into_iter().map(|x| Collection::new(x.crypto_manager(&self.account_crypto_manager)?, x)).collect();

        Ok(CollectionListResponse {
            data: data?,
            done: response.done,
            stoken: response.stoken,
            removed_memberships: response.removed_memberships,
        })
    }

    pub fn upload(&self, collection: &Collection, options: Option<&FetchOptions>) -> Result<()> {
        let col = &collection.col;
        if col._is_new() {
            self.collection_manager_online.create(&col, options)?;
        } else {
            let item_manager_online = ItemManagerOnline::new(Arc::clone(&self.client), &col);
            item_manager_online.batch(vec![col.item()].into_iter(), std::iter::empty(), options)?;
        }

        Ok(())
    }

    pub fn transaction(&self, collection: &Collection, options: Option<&FetchOptions>) -> Result<()> {
        let col = &collection.col;
        if col._is_new() {
            self.collection_manager_online.create(&col, options)?;
        } else {
            let item_manager_online = ItemManagerOnline::new(Arc::clone(&self.client), &col);
            item_manager_online.transaction(vec![col.item()].into_iter(), std::iter::empty(), options)?;
        }

        Ok(())
    }

    pub fn cache_load(&self, cached: &[u8]) -> Result<Collection> {
        let col = EncryptedCollection::cache_load(cached)?;
        Collection::new(col.crypto_manager(&self.account_crypto_manager)?, col)
    }

    pub fn cache_save(&self, collection: &Collection) -> Result<Vec<u8>> {
        collection.col.cache_save()
    }

    pub fn cache_save_with_content(&self, collection: &Collection) -> Result<Vec<u8>> {
        collection.col.cache_save_with_content()
    }

    pub fn item_manager(&self, collection: &Collection) -> Result<ItemManager> {
        ItemManager::new(Arc::clone(&self.client), Arc::clone(&collection.cm), collection)
    }

    pub fn member_manager(&self, collection: &Collection) -> Result<CollectionMemberManager> {
        CollectionMemberManager::new(Arc::clone(&self.client), collection)
    }
}

pub struct ItemManager {
    collection_crypto_manager: Arc<CollectionCryptoManager>,
    item_manager_online: ItemManagerOnline,
}

impl ItemManager {
    fn new(client: Arc<Client>, collection_crypto_manager: Arc<CollectionCryptoManager>, collection: &Collection) -> Result<Self> {
        let item_manager_online = ItemManagerOnline::new(Arc::clone(&client), &collection.col);
        Ok(Self {
            collection_crypto_manager,
            item_manager_online,
        })
    }

    pub fn create<T: MsgPackSerilization>(&self, meta: &T, content: &[u8]) -> Result<Item> {
        let meta = meta.to_msgpack()?;
        let encrypted_item = EncryptedItem::new(&self.collection_crypto_manager, &meta, content)?;
        Item::new(encrypted_item.crypto_manager(&self.collection_crypto_manager)?, encrypted_item)
    }

    pub fn fetch(&self, item_uid: &StrBase64, options: Option<&FetchOptions>) -> Result<Item> {
        let encrypted_item = self.item_manager_online.fetch(&item_uid, options)?;
        Item::new(encrypted_item.crypto_manager(&self.collection_crypto_manager)?, encrypted_item)
    }

    pub fn list(&self, options: Option<&FetchOptions>) -> Result<ItemListResponse<Item>> {
        let response = self.item_manager_online.list(options)?;

        let data: Result<Vec<Item>> = response.data.into_iter().map(|x| Item::new(x.crypto_manager(&self.collection_crypto_manager)?, x)).collect();
        Ok(ItemListResponse {
            data: data?,
            done: response.done,
            stoken: response.stoken,
        })
    }

    pub fn item_revisions(&self, item: &Item, options: Option<&FetchOptions>) -> Result<IteratorListResponse<Item>> {
        let item = &item.item;
        let response = self.item_manager_online.item_revisions(item, options)?;

        let data: Result<Vec<Item>> = response.data.into_iter().map(|x| Item::new(x.crypto_manager(&self.collection_crypto_manager)?, x)).collect();
        Ok(IteratorListResponse {
            data: data?,
            done: response.done,
            iterator: response.iterator,
        })
    }


    pub fn fetch_updates<'a, I>(&self, items: I, options: Option<&FetchOptions>) -> Result<ItemListResponse<Item>>
        where I: Iterator<Item = &'a Item>
        {

        let items = items.map(|x| &x.item);
        let response = self.item_manager_online.fetch_updates(items, options)?;
        let data: Result<Vec<Item>> = response.data.into_iter().map(|x| Item::new(x.crypto_manager(&self.collection_crypto_manager)?, x)).collect();
        Ok(ItemListResponse {
            data: data?,
            done: response.done,
            stoken: response.stoken,
        })
    }

    pub fn batch<'a, I>(&self, items: I, options: Option<&FetchOptions>) -> Result<()>
        where I: Iterator<Item = &'a Item>
        {

        let items = items.map(|x| &x.item);
        let deps = std::iter::empty();
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
        let deps = std::iter::empty();
        self.item_manager_online.transaction(items, deps, options)
    }

    pub fn transaction_deps<'a, I, J>(&self, items: I, deps: J, options: Option<&FetchOptions>) -> Result<()>
        where I: Iterator<Item = &'a Item>, J: Iterator<Item = &'a Item>
        {

        let items = items.map(|x| &x.item);
        let deps = deps.map(|x| &x.item);
        self.item_manager_online.transaction(items, deps, options)
    }

    pub fn cache_load(&self, cached: &[u8]) -> Result<Item> {
        let item = EncryptedItem::cache_load(cached)?;
        Item::new(item.crypto_manager(&self.collection_crypto_manager)?, item)
    }

    pub fn cache_save(&self, item: &Item) -> Result<Vec<u8>> {
        item.item.cache_save()
    }

    pub fn cache_save_with_content(&self, item: &Item) -> Result<Vec<u8>> {
        item.item.cache_save_with_content()
    }
}

pub struct CollectionInvitationManager {
    account_crypto_manager: Arc<AccountCryptoManager>,
    identity_crypto_manager: BoxCryptoManager,
    invitation_manager_online: CollectionInvitationManagerOnline,
}

impl CollectionInvitationManager {
    fn new(client: Arc<Client>, account_crypto_manager: Arc<AccountCryptoManager>, identity_crypto_manager: BoxCryptoManager) -> Result<Self> {
        let invitation_manager_online = CollectionInvitationManagerOnline::new(Arc::clone(&client));
        Ok(Self {
            account_crypto_manager,
            identity_crypto_manager,
            invitation_manager_online,
        })
    }

    pub fn list_incoming(&self, options: Option<&FetchOptions>) -> Result<IteratorListResponse<SignedInvitation>> {
        self.invitation_manager_online.list_incoming(options)
    }

    pub fn list_outgoing(&self, options: Option<&FetchOptions>) -> Result<IteratorListResponse<SignedInvitation>> {
        self.invitation_manager_online.list_outgoing(options)
    }

    pub fn accept(&self, invitation: &SignedInvitation) -> Result<()> {
        let decrypted_encryption_key = invitation.decrypted_encryption_key(&self.identity_crypto_manager)?;
        let encryption_key = self.account_crypto_manager.0.encrypt(&decrypted_encryption_key, None)?;
        self.invitation_manager_online.accept(invitation, &encryption_key)
    }

    pub fn reject(&self, invitation: &SignedInvitation) -> Result<()> {
        self.invitation_manager_online.reject(invitation)
    }

    pub fn fetch_user_profile(&self, username: &str) -> Result<UserProfile> {
        self.invitation_manager_online.fetch_user_profile(username)
    }

    pub fn invite(&self, collection: &Collection, username: &str, pubkey: &[u8], access_level: &CollectionAccessLevel) -> Result<()> {
        let invitation = collection.col.create_invitation(&self.account_crypto_manager, &self.identity_crypto_manager, username, pubkey, access_level)?;
        self.invitation_manager_online.invite(&invitation)
    }

    pub fn disinvite(&self, invitation: &SignedInvitation) -> Result<()> {
        self.invitation_manager_online.disinvite(invitation)
    }

    pub fn pubkey(&self) -> &[u8] {
        self.identity_crypto_manager.pubkey()
    }
}

pub struct CollectionMemberManager {
    member_manager_online: CollectionMemberManagerOnline,
}

impl CollectionMemberManager {
    fn new(client: Arc<Client>, collection: &Collection) -> Result<Self> {
        let member_manager_online = CollectionMemberManagerOnline::new(Arc::clone(&client), &collection.col);
        Ok(Self {
            member_manager_online,
        })
    }

    pub fn list(&self, options: Option<&FetchOptions>) -> Result<IteratorListResponse<CollectionMember>> {
        self.member_manager_online.list(options)
    }

    pub fn remove(&self, username: &str) -> Result<()> {
        self.member_manager_online.remove(username)
    }

    pub fn leave(&self) -> Result<()> {
        self.member_manager_online.leave()
    }

    pub fn modify_access_level(&self, username: &str, access_level: &CollectionAccessLevel) -> Result<()> {
        self.member_manager_online.modify_access_level(username, access_level)
    }
}


#[derive(Clone)]
pub struct Collection {
    col: EncryptedCollection,
    cm: Arc<CollectionCryptoManager>,
}

impl Collection {
    fn new(crypto_manager: CollectionCryptoManager, encrypted_collection: EncryptedCollection) -> Result<Self> {
        Ok(Self {
            col: encrypted_collection,
            cm: Arc::new(crypto_manager),
        })
    }

    pub fn verify(&self) -> Result<bool> {
        self.col.verify(&self.cm)
    }

    pub fn set_meta<T: MsgPackSerilization>(&mut self, meta: &T) -> Result<()> {
        let meta = meta.to_msgpack()?;
        self.col.set_meta(&self.cm, &meta)
    }

    pub fn meta(&self) -> Result<CollectionMetadata> {
        self.meta_generic::<CollectionMetadata>()
    }

    pub fn meta_generic<T: MsgPackSerilization>(&self) -> Result<T::Output> {
        let decrypted = self.col.meta(&self.cm)?;
        T::from_msgpack(&decrypted)
    }

    pub fn set_meta_raw(&mut self, meta: &[u8]) -> Result<()> {
        self.col.set_meta(&self.cm, &meta)
    }

    pub fn meta_raw(&self) -> Result<Vec<u8>> {
        self.col.meta(&self.cm)
    }

    pub fn set_content(&mut self, content: &[u8]) -> Result<()> {
        self.col.set_content(&self.cm, content)
    }

    pub fn content(&self) -> Result<Vec<u8>> {
        self.col.content(&self.cm)
    }

    pub fn delete(&mut self) -> Result<()> {
        self.col.delete(&self.cm)
    }

    pub fn is_deleted(&self) -> bool {
        self.col.is_deleted()
    }

    pub fn uid(&self) -> &str {
        self.col.uid()
    }

    pub fn etag(&self) -> &str {
        self.col.etag()
    }

    pub fn stoken(&self) -> Option<&str> {
        self.col.stoken()
    }

    pub fn access_level(&self) -> &CollectionAccessLevel {
        self.col.access_level()
    }

    pub fn item(&self) -> Result<Item> {
        let encrypted_item = self.col.item();
        let crypto_manager = encrypted_item.crypto_manager(&self.cm)?;
        Item::new(crypto_manager, encrypted_item.clone())
    }
}

#[derive(Clone)]
pub struct Item {
    item: EncryptedItem,
    cm: Arc<ItemCryptoManager>,
}

impl Item {
    fn new(crypto_manager: ItemCryptoManager, encrypted_item: EncryptedItem) -> Result<Self> {
        Ok(Self {
            item: encrypted_item,
            cm: Arc::new(crypto_manager),
        })
    }

    pub fn verify(&self) -> Result<bool> {
        self.item.verify(&self.cm)
    }

    pub fn set_meta<T: MsgPackSerilization>(&mut self, meta: &T) -> Result<()> {
        let meta = meta.to_msgpack()?;
        self.item.set_meta(&self.cm, &meta)
    }

    pub fn meta(&self) -> Result<ItemMetadata> {
        self.meta_generic::<ItemMetadata>()
    }

    pub fn meta_generic<T: MsgPackSerilization>(&self) -> Result<T::Output> {
        let decrypted = self.item.meta(&self.cm)?;
        T::from_msgpack(&decrypted)
    }

    pub fn set_meta_raw(&mut self, meta: &[u8]) -> Result<()> {
        self.item.set_meta(&self.cm, &meta)
    }

    pub fn meta_raw(&self) -> Result<Vec<u8>> {
        self.item.meta(&self.cm)
    }

    pub fn set_content(&mut self, content: &[u8]) -> Result<()> {
        self.item.set_content(&self.cm, content)
    }

    pub fn content(&self) -> Result<Vec<u8>> {
        self.item.content(&self.cm)
    }

    pub fn delete(&mut self) -> Result<()> {
        self.item.delete(&self.cm)
    }

    pub fn is_deleted(&self) -> bool {
        self.item.is_deleted()
    }

    pub fn uid(&self) -> &str {
        self.item.uid()
    }

    pub fn etag(&self) -> &str {
        self.item.etag()
    }
}

pub(crate) fn test_chunk_uids(item: &Item) -> Vec<String> {
    item.item.test_chunk_uids()
}
