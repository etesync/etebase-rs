// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate rmp_serde;

use std::convert::TryInto;
use std::iter;
use std::sync::Arc;

use crate::utils::{PRIVATE_KEY_SIZE, SALT_SIZE};
use serde::{Deserialize, Serialize};

use super::{
    crypto::{derive_key, BoxCryptoManager, CryptoManager, LoginCryptoManager},
    encrypted_models::{
        AccountCryptoManager, CollectionAccessLevel, CollectionCryptoManager, EncryptedCollection,
        EncryptedItem, ItemCryptoManager, ItemMetadata, SignedInvitation, SignedInvitationContent,
    },
    error::{Error, Result},
    http_client::Client,
    online_managers::{
        Authenticator, CollectionInvitationManagerOnline, CollectionListResponse,
        CollectionManagerOnline, CollectionMember, CollectionMemberManagerOnline, FetchOptions,
        ItemListResponse, ItemManagerOnline, IteratorListResponse, LoginBodyResponse,
        LoginChallange, LoginResponseUser, User, UserProfile,
    },
    utils::{
        buffer_unpad, from_base64, randombytes_array, to_base64, MsgPackSerilization, StrBase64,
        SYMMETRIC_KEY_SIZE,
    },
};

struct MainCryptoManager(CryptoManager);

impl MainCryptoManager {
    pub fn new(key: &[u8; 32], version: u8) -> Result<MainCryptoManager> {
        let context = b"Main    ";

        Ok(MainCryptoManager(CryptoManager::new(
            key, context, version,
        )?))
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

        Ok(Self(CryptoManager::new(key, context, version)?))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountData<'a> {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub key: &'a [u8],
    pub user: LoginResponseUser,
    pub server_url: &'a str,
    pub auth_token: Option<&'a str>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountDataStored<'a> {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub encrypted_data: &'a [u8],
}

/// The main object for all user interactions and data manipulation, representing an authenticated
/// user account.
pub struct Account {
    main_key: [u8; SYMMETRIC_KEY_SIZE],
    version: u8,
    user: LoginResponseUser,
    client: Arc<Client>,
    account_crypto_manager: Arc<AccountCryptoManager>,
}

impl Account {
    /// Check whether the [`Client`] is pointing to a valid Etebase server
    ///
    /// # Arguments:
    /// * `client` - the already setup [`Client`] object
    #[deprecated = "Use `Client::is_server_valid` instead"]
    pub fn is_etebase_server(client: &Client) -> Result<bool> {
        client.is_server_valid()
    }

    /// Creates a new user on the server and returns a handle to it. The user is authenticated
    /// using the given `password`.
    pub fn signup(client: Client, user: &User, password: &str) -> Result<Self> {
        super::init()?;

        // only the first 16 bytes of the salt are used for key generation, but previous
        // implementations have always generated 32 bytes regardless.
        let salt = randombytes_array::<32>();
        let main_key = derive_key(&salt[..16].try_into().unwrap(), password)?;

        Self::signup_common(client, user, main_key, &salt)
    }

    /// Creates a new user on the server and returns a handle to it. The user is authenticated
    /// using a cryptographically secure random 32-byte `main_key` instead of a password.
    pub fn signup_key(client: Client, user: &User, main_key: &[u8]) -> Result<Self> {
        super::init()?;

        let main_key: [u8; 32] = main_key
            .try_into()
            .map_err(|_| Error::ProgrammingError("Key should be exactly 32 bytes long."))?;

        // Since the key is provided as-is instead of being generated from a password+hash, this is
        // not actually used for anything; generate it anyway for consistency.
        let salt = randombytes_array::<32>();

        Self::signup_common(client, user, main_key, &salt)
    }

    fn signup_common(
        mut client: Client,
        user: &User,
        main_key: [u8; SYMMETRIC_KEY_SIZE],
        salt: &[u8],
    ) -> Result<Self> {
        let authenticator = Authenticator::new(&client);
        let version = super::CURRENT_VERSION;

        let main_crypto_manager = MainCryptoManager::new(&main_key, version)?;
        let login_crypto_manager = main_crypto_manager.login_crypto_manager()?;

        let identity_crypto_manager = BoxCryptoManager::keygen(None)?;

        let account_key = randombytes_array();
        let content = [&account_key, identity_crypto_manager.privkey()].concat();
        let encrypted_content = main_crypto_manager.0.encrypt(&content, None)?;

        let login_response = authenticator.signup(
            user,
            salt,
            login_crypto_manager.pubkey(),
            identity_crypto_manager.pubkey(),
            &encrypted_content,
        )?;

        client.set_token(Some(&login_response.token));

        let account_crypto_manager = main_crypto_manager.account_crypto_manager(&account_key)?;

        let ret = Self {
            main_key,
            version,
            user: login_response.user,
            client: Arc::new(client),
            account_crypto_manager: Arc::new(account_crypto_manager),
        };

        Ok(ret)
    }

    /// Authenticates a user using their `password` and returns an `Account` handle on success.
    pub fn login(client: Client, username: &str, password: &str) -> Result<Self> {
        super::init()?;

        let authenticator = Authenticator::new(&client);
        let login_challenge = match authenticator.get_login_challenge(username) {
            Err(Error::Unauthorized(s)) => {
                // FIXME: fragile, we should have a proper error value or actually use codes
                if s == "User not properly init" {
                    let user = User::new(username, "init@localhost");
                    return Self::signup(client, &user, password);
                } else {
                    return Err(Error::Unauthorized(s));
                }
            }
            rest => rest?,
        };

        // A 32-byte value is generated during signup, but only first 16 bytes are used for key
        // generation.
        let salt = login_challenge
            .salt
            .get(..SALT_SIZE)
            .ok_or(Error::Encryption(
                "Salt obtained from login challenge too short: expected at least 16 bytes",
            ))?
            .try_into()
            .unwrap();
        let main_key = derive_key(&salt, password)?;

        Self::login_common(client, username, main_key, login_challenge)
    }

    /// Authenticates a user using the same `main_key` as was provided to
    /// [`signup_key`](Self::signup_key) and returns an `Account` handle on success.
    pub fn login_key(client: Client, username: &str, main_key: &[u8]) -> Result<Self> {
        super::init()?;

        let main_key: [u8; 32] = main_key
            .try_into()
            .map_err(|_| Error::ProgrammingError("Key should be exactly 32 bytes long."))?;

        let authenticator = Authenticator::new(&client);
        let login_challenge = match authenticator.get_login_challenge(username) {
            Err(Error::Unauthorized(s)) => {
                // FIXME: fragile, we should have a proper error value or actually use codes
                if s == "User not properly init" {
                    let user = User::new(username, "init@localhost");
                    return Self::signup_key(client, &user, &main_key[..]);
                } else {
                    return Err(Error::Unauthorized(s));
                }
            }
            rest => rest?,
        };

        Self::login_common(client, username, main_key, login_challenge)
    }

    fn login_common(
        mut client: Client,
        username: &str,
        main_key: [u8; SYMMETRIC_KEY_SIZE],
        login_challenge: LoginChallange,
    ) -> Result<Self> {
        let authenticator = Authenticator::new(&client);

        let version = login_challenge.version;

        let main_crypto_manager = MainCryptoManager::new(&main_key, version)?;
        let login_crypto_manager = main_crypto_manager.login_crypto_manager()?;

        let response_struct = LoginBodyResponse {
            username,
            challenge: &login_challenge.challenge,
            host: client
                .server_url()
                .host_str()
                .unwrap_or_else(|| client.server_url().as_str()),
            action: "login",
        };
        let response = rmp_serde::to_vec_named(&response_struct)?;

        let signature = login_crypto_manager.sign_detached(&response)?;

        let login_response = authenticator.login(&response, &signature)?;

        client.set_token(Some(&login_response.token));

        let content = main_crypto_manager
            .0
            .decrypt(&login_response.user.encrypted_content, None)?;

        // The content is the concatenation of the account key and the private key
        let account_key = content
            .get(..SYMMETRIC_KEY_SIZE)
            .ok_or(Error::Encryption(
                "Server's login response too short to contain account key",
            ))?
            .try_into()
            .unwrap();
        let account_crypto_manager = main_crypto_manager.account_crypto_manager(account_key)?;

        let ret = Self {
            main_key,
            version,
            user: login_response.user,
            client: Arc::new(client),
            account_crypto_manager: Arc::new(account_crypto_manager),
        };

        Ok(ret)
    }

    /// Fetch a new auth token for the account and update the [`Account`] object with it
    pub fn fetch_token(&mut self) -> Result<()> {
        let mut client = (*self.client).clone();
        client.set_token(None);
        let authenticator = Authenticator::new(&client);
        let login_challenge = authenticator.get_login_challenge(&self.user.username)?;

        let version = self.version;

        let username = &self.user.username;
        let main_crypto_manager = MainCryptoManager::new(&self.main_key, version)?;
        let login_crypto_manager = main_crypto_manager.login_crypto_manager()?;

        let response_struct = LoginBodyResponse {
            username,
            challenge: &login_challenge.challenge,
            host: self
                .client
                .server_url()
                .host_str()
                .unwrap_or_else(|| self.client.server_url().as_str()),
            action: "login",
        };
        let response = rmp_serde::to_vec_named(&response_struct)?;

        let signature = login_crypto_manager.sign_detached(&response)?;

        let login_response = authenticator.login(&response, &signature)?;

        client.set_token(Some(&login_response.token));
        self.client = Arc::new(client);

        Ok(())
    }

    /// Change the server URL for this account handle
    ///
    /// See also [`Client::set_server_url`].
    pub fn force_server_url(&mut self, api_base: &str) -> Result<()> {
        let mut client = (*self.client).clone();
        client.set_server_url(api_base)?;
        self.client = Arc::new(client);

        Ok(())
    }

    /// Change the user's login password. If the account currently uses key-based login, the key is
    /// invalidated and subsequent logins have to use the password.
    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        let authenticator = Authenticator::new(&self.client);
        let version = self.version;
        let username = &self.user.username;
        let main_key = &self.main_key;
        let login_challenge = authenticator.get_login_challenge(username)?;

        let old_main_crypto_manager = MainCryptoManager::new(main_key, version)?;
        let content = old_main_crypto_manager
            .0
            .decrypt(&self.user.encrypted_content, None)?;
        let old_login_crypto_manager = old_main_crypto_manager.login_crypto_manager()?;

        let salt = login_challenge
            .salt
            .get(..SALT_SIZE)
            .ok_or(Error::Encryption(
                "Salt obtained from login challenge too short: expected at least 16 bytes",
            ))?
            .try_into()
            .unwrap();
        let main_key = derive_key(&salt, new_password)?;
        let main_crypto_manager = MainCryptoManager::new(&main_key, version)?;
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
            host: self
                .client
                .server_url()
                .host_str()
                .unwrap_or_else(|| self.client.server_url().as_str()),
            action: "changePassword",

            login_pubkey: login_crypto_manager.pubkey(),
            encrypted_content: &encrypted_content,
        };
        let response = rmp_serde::to_vec_named(&response_struct)?;

        let signature = old_login_crypto_manager.sign_detached(&response)?;

        authenticator.change_password(&response, &signature)?;

        self.main_key = main_key;
        self.user.encrypted_content = encrypted_content;
        Ok(())
    }

    /// Fetch the link to the user dashboard of the account
    pub fn fetch_dashboard_url(&self) -> Result<String> {
        let authenticator = Authenticator::new(&self.client);

        authenticator.fetch_dashboard_url()
    }

    /// Logout the user from the current session and invalidate the authentication token
    pub fn logout(&self) -> Result<()> {
        let authenticator = Authenticator::new(&self.client);

        authenticator.logout()
    }

    /// Serializes the account object to a string for restoring it later using [`restore`](Self::restore).
    ///
    /// The data should be encrypted using a 32-byte `encryption_key` for added security.
    pub fn save(&self, encryption_key: Option<&[u8]>) -> Result<String> {
        let version = super::CURRENT_VERSION;

        let encryption_key = if let Some(encryption_key) = encryption_key {
            encryption_key.try_into().map_err(|_| {
                Error::ProgrammingError("Encryption key must be exactly 32 bytes long")
            })?
        } else {
            &[0; 32]
        };

        let crypto_manager = StorageCryptoManager::new(encryption_key, version)?;
        let account_data = AccountData {
            user: self.user.clone(),
            version,
            key: &crypto_manager.0.encrypt(&self.main_key, None)?,
            auth_token: self.client.token(),
            server_url: self.client.server_url().as_str(),
        };
        let serialized = rmp_serde::to_vec_named(&account_data)?;

        let ret = AccountDataStored {
            version,
            encrypted_data: &crypto_manager.0.encrypt(&serialized, Some(&[version]))?,
        };
        let serialized = rmp_serde::to_vec_named(&ret)?;

        to_base64(&serialized)
    }

    /// Deserialize and return the [`Account`] object from the string obtained using
    /// [`save`](Self::save).
    ///
    /// # Arguments:
    /// * `client` - the already setup [`Client`] object
    /// * `account_data_stored` - the stored account string
    /// * `encryption_key` - the same encryption key passed to [`save`](Self::save) while saving the account
    // FIXME: we don't actually need a full `Client` here, only its `ClientImplementation`
    pub fn restore(
        mut client: Client,
        account_data_stored: &str,
        encryption_key: Option<&[u8]>,
    ) -> Result<Self> {
        let encryption_key = if let Some(encryption_key) = encryption_key {
            encryption_key.try_into().map_err(|_| {
                Error::ProgrammingError("Encryption key must be exactly 32 bytes long")
            })?
        } else {
            &[0; 32]
        };

        let account_data_stored = from_base64(account_data_stored)?;
        let account_data_stored: AccountDataStored = rmp_serde::from_slice(&account_data_stored)?;
        let version = account_data_stored.version;

        let crypto_manager = StorageCryptoManager::new(encryption_key, version)?;
        let decrypted = crypto_manager
            .0
            .decrypt(account_data_stored.encrypted_data, Some(&[version]))?;
        let account_data: AccountData = rmp_serde::from_slice(&decrypted)?;

        client.set_token(account_data.auth_token);
        client.set_server_url(account_data.server_url)?;

        let main_key = crypto_manager.0.decrypt(account_data.key, None)?;
        let main_key = main_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Encryption("Restored main key has wrong size"))?;

        let main_crypto_manager = MainCryptoManager::new(&main_key, version)?;
        let content = main_crypto_manager
            .0
            .decrypt(&account_data.user.encrypted_content, None)?;

        // The content is the concatenation of the account key and the private key
        let account_key = content
            .get(..SYMMETRIC_KEY_SIZE)
            .ok_or(Error::Encryption(
                "Server's login response too short to contain account key",
            ))?
            .try_into()
            .unwrap();
        let account_crypto_manager = main_crypto_manager.account_crypto_manager(account_key)?;

        Ok(Self {
            user: account_data.user,
            version: account_data.version,
            main_key,
            client: Arc::new(client),
            account_crypto_manager: Arc::new(account_crypto_manager),
        })
    }

    /// Return a [`CollectionManager`] for creating, fetching and uploading collections
    pub fn collection_manager(&self) -> Result<CollectionManager> {
        CollectionManager::new(
            Arc::clone(&self.client),
            Arc::clone(&self.account_crypto_manager),
        )
    }

    /// Return a [`CollectionInvitationManager`] for managing collection invitations
    pub fn invitation_manager(&self) -> Result<CollectionInvitationManager> {
        CollectionInvitationManager::new(
            Arc::clone(&self.client),
            Arc::clone(&self.account_crypto_manager),
            self.identity_crypto_manager()?,
        )
    }

    fn main_crypto_manager(&self) -> Result<MainCryptoManager> {
        let version = self.version;
        MainCryptoManager::new(&self.main_key, version)
    }

    fn identity_crypto_manager(&self) -> Result<BoxCryptoManager> {
        let main_crypto_manager = self.main_crypto_manager()?;
        let content = main_crypto_manager
            .0
            .decrypt(&self.user.encrypted_content, None)?;

        // The content is the concatenation of the account key and the private key
        let privkey = content
            .get(SYMMETRIC_KEY_SIZE..(SYMMETRIC_KEY_SIZE + PRIVATE_KEY_SIZE))
            .ok_or(Error::Encryption(
                "Server's login response too short to contain private key",
            ))?
            .try_into()
            .unwrap();
        main_crypto_manager.identity_crypto_manager(privkey)
    }
}

/// A manager for managing collection operations like creation and fetching
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

    /// Create a new [`Collection`]
    ///
    /// # Arguments:
    /// * `collection_type` - the type of [`Item`]s stored in the collection
    /// * `meta` - the [`ItemMetadata`] for the collection
    /// * `content` - the collection's content as a byte array. This is unrelated to the [`Item`]s in the collection.
    pub fn create<T: MsgPackSerilization>(
        &self,
        collection_type: &str,
        meta: &T,
        content: &[u8],
    ) -> Result<Collection> {
        let meta = meta.to_msgpack()?;
        self.create_raw(collection_type, &meta, content)
    }

    /// Create a new [`Collection`] using raw metadata
    ///
    /// Unlike [`create`](Self::create), this receives the metadata as valid [`ItemMetadata`]-like struct encoded using `msgpack`.
    /// This can be used to create collections with custom metadata types.
    ///
    /// # Arguments:
    /// * `collection_type` - the type of [`Item`]s stored in the collection
    /// * `meta` - the metadata for the collection as a byte array
    /// * `content` - the collection's content as a byte array. This is unrelated to the [`Item`]s in the collection.
    pub fn create_raw(
        &self,
        collection_type: &str,
        meta: &[u8],
        content: &[u8],
    ) -> Result<Collection> {
        let encrypted_collection =
            EncryptedCollection::new(&self.account_crypto_manager, collection_type, meta, content)?;
        Collection::new(
            self.account_crypto_manager.clone(),
            encrypted_collection.crypto_manager(&self.account_crypto_manager)?,
            encrypted_collection,
        )
    }

    /// Fetch a single [`Collection`] from the server using its UID
    ///
    /// # Arguments:
    /// * `col_uid` - the UID of the collection to be fetched
    /// * `options` - parameters to tune or optimize the fetch
    pub fn fetch(&self, col_uid: &StrBase64, options: Option<&FetchOptions>) -> Result<Collection> {
        let encrypted_collection = self.collection_manager_online.fetch(col_uid, options)?;
        Collection::new(
            self.account_crypto_manager.clone(),
            encrypted_collection.crypto_manager(&self.account_crypto_manager)?,
            encrypted_collection,
        )
    }

    /// Fetch all [`Collection`]s of a specific type from the server and return a [`CollectionListResponse`]
    ///
    /// # Arguments:
    /// * `collection_type` - the type of [`Item`]s stored in the collection
    /// * `options` - parameters to tune or optimize the fetch
    pub fn list(
        &self,
        collection_type: &str,
        options: Option<&FetchOptions>,
    ) -> Result<CollectionListResponse<Collection>> {
        self.list_multi(iter::once(collection_type), options)
    }

    /// Fetch all [`Collection`]s of the supplied types from the server and return a [`CollectionListResponse`]
    ///
    /// # Arguments:
    /// * `collection_type` - array of strings denoting the collection types
    /// * `options` - parameters to tune or optimize the fetch
    pub fn list_multi<I>(
        &self,
        collection_types: I,
        options: Option<&FetchOptions>,
    ) -> Result<CollectionListResponse<Collection>>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let collection_type_uids = collection_types.into_iter().map(|x| {
            self.account_crypto_manager
                .collection_type_to_uid(x.as_ref())
                .unwrap()
        });
        let response = self
            .collection_manager_online
            .list_multi(collection_type_uids, options)?;

        let data: Result<Vec<Collection>> = response
            .data
            .into_iter()
            .map(|x| {
                Collection::new(
                    self.account_crypto_manager.clone(),
                    x.crypto_manager(&self.account_crypto_manager)?,
                    x,
                )
            })
            .collect();

        Ok(CollectionListResponse {
            data: data?,
            done: response.done,
            stoken: response.stoken,
            removed_memberships: response.removed_memberships,
        })
    }

    /// Upload a [`Collection`]
    ///
    /// # Arguments:
    /// * `collection` - the collection object to be uploaded
    /// * `options` - parameters to tune or optimize the upload
    pub fn upload(&self, collection: &Collection, options: Option<&FetchOptions>) -> Result<()> {
        let col = &collection.col;
        if col._is_new() {
            self.collection_manager_online.create(col, options)?;
        } else {
            let item_manager_online = ItemManagerOnline::new(Arc::clone(&self.client), col);
            item_manager_online.batch(vec![col.item()].into_iter(), std::iter::empty(), options)?;
        }

        Ok(())
    }

    /// Upload a [`Collection`] using a transaction
    ///
    /// This call ensures that the collection hasn't changed since we last fetched it
    ///
    /// # Arguments:
    /// * `collection` - the collection object to be uploaded
    /// * `options` - parameters to tune or optimize the upload
    pub fn transaction(
        &self,
        collection: &Collection,
        options: Option<&FetchOptions>,
    ) -> Result<()> {
        let col = &collection.col;
        if col._is_new() {
            self.collection_manager_online.create(col, options)?;
        } else {
            let item_manager_online = ItemManagerOnline::new(Arc::clone(&self.client), col);
            item_manager_online.transaction(
                vec![col.item()].into_iter(),
                std::iter::empty(),
                options,
            )?;
        }

        Ok(())
    }

    /// Load and return a cached [`Collection`] object from a byte buffer
    ///
    /// # Arguments:
    /// * `cached` - the byte buffer holding the cached collection obtained using
    ///   [`cache_save`](Self::cache_save)
    pub fn cache_load(&self, cached: &[u8]) -> Result<Collection> {
        let col = EncryptedCollection::cache_load(cached)?;
        Collection::new(
            self.account_crypto_manager.clone(),
            col.crypto_manager(&self.account_crypto_manager)?,
            col,
        )
    }

    /// Save the [`Collection`] object to a byte buffer for caching
    ///
    /// The collection can later be loaded using [`cache_load`](Self::cache_load)
    ///
    /// # Arguments:
    /// * `collection` - the collection object to be cached
    pub fn cache_save(&self, collection: &Collection) -> Result<Vec<u8>> {
        collection.col.cache_save()
    }

    /// Save the [`Collection`] object and its content to a byte buffer for caching
    ///
    /// The collection can later be loaded using [`cache_load`](Self::cache_load)
    ///
    /// # Arguments:
    /// * `collection` - the collection object to be cached
    pub fn cache_save_with_content(&self, collection: &Collection) -> Result<Vec<u8>> {
        collection.col.cache_save_with_content()
    }

    /// Return the [`ItemManager`] for the supplied collection
    ///
    /// # Arguments:
    /// * `collection` - the collection for which the [`ItemManager`] is required
    pub fn item_manager(&self, collection: &Collection) -> Result<ItemManager> {
        ItemManager::new(
            Arc::clone(&self.client),
            Arc::clone(&collection.cm),
            collection,
        )
    }

    /// Return the [`CollectionMemberManager`] for the supplied collection
    ///
    /// # Arguments:
    /// * `collection` - the collection for which the [`ItemManager`] is required
    pub fn member_manager(&self, collection: &Collection) -> Result<CollectionMemberManager> {
        CollectionMemberManager::new(Arc::clone(&self.client), collection)
    }
}

/// A manager for managing item operations like creation and fetching
pub struct ItemManager {
    collection_crypto_manager: Arc<CollectionCryptoManager>,
    item_manager_online: ItemManagerOnline,
}

impl ItemManager {
    fn new(
        client: Arc<Client>,
        collection_crypto_manager: Arc<CollectionCryptoManager>,
        collection: &Collection,
    ) -> Result<Self> {
        let item_manager_online = ItemManagerOnline::new(Arc::clone(&client), &collection.col);
        Ok(Self {
            collection_crypto_manager,
            item_manager_online,
        })
    }

    /// Create a new [`Item`]
    ///
    /// # Arguments:
    /// * `meta` - the [`ItemMetadata`] for the item
    /// * `content` - the item's content as a byte array
    pub fn create<T: MsgPackSerilization>(&self, meta: &T, content: &[u8]) -> Result<Item> {
        let meta = meta.to_msgpack()?;
        self.create_raw(&meta, content)
    }

    /// Create a new [`Item`] using raw metadata
    ///
    /// Unlike [`create`](Self::create), this receives the metadata as valid [`ItemMetadata`]-like struct encoded using `msgpack`.
    /// This can be used to create items with custom metadata types.
    ///
    /// # Arguments:
    /// * `meta` - the metadata for the item as a byte array
    /// * `content` - the item's content as a byte array
    pub fn create_raw(&self, meta: &[u8], content: &[u8]) -> Result<Item> {
        let encrypted_item = EncryptedItem::new(&self.collection_crypto_manager, meta, content)?;
        Item::new(
            encrypted_item.crypto_manager(&self.collection_crypto_manager)?,
            encrypted_item,
        )
    }

    /// Fetch a single [`Item`] from the server using its UID
    ///
    /// See [`fetch_multi`](Self::fetch_multi) for fetching multiple items
    ///
    /// # Arguments:
    /// * `item_uid` - the UID of the collection to be fetched
    /// * `options` - parameters to tune or optimize the fetch
    pub fn fetch(&self, item_uid: &StrBase64, options: Option<&FetchOptions>) -> Result<Item> {
        let encrypted_item = self.item_manager_online.fetch(item_uid, options)?;
        Item::new(
            encrypted_item.crypto_manager(&self.collection_crypto_manager)?,
            encrypted_item,
        )
    }

    /// Fetch all [`Item`]s of a collection and return an [`ItemListResponse`]
    ///
    /// # Arguments:
    /// * `options` - parameters to tune or optimize the fetch
    pub fn list(&self, options: Option<&FetchOptions>) -> Result<ItemListResponse<Item>> {
        let response = self.item_manager_online.list(options)?;

        let data: Result<Vec<Item>> = response
            .data
            .into_iter()
            .map(|x| Item::new(x.crypto_manager(&self.collection_crypto_manager)?, x))
            .collect();
        Ok(ItemListResponse {
            data: data?,
            done: response.done,
            stoken: response.stoken,
        })
    }

    /// Fetch and return a list response of [`Item`]s with each item as the revision
    ///
    /// # Arguments:
    /// * `item` - the item for which to fetch the revision history
    /// * `options` - parameters to tune or optimize the fetch
    pub fn item_revisions(
        &self,
        item: &Item,
        options: Option<&FetchOptions>,
    ) -> Result<IteratorListResponse<Item>> {
        let item = &item.item;
        let response = self.item_manager_online.item_revisions(item, options)?;

        let data: Result<Vec<Item>> = response
            .data
            .into_iter()
            .map(|x| Item::new(x.crypto_manager(&self.collection_crypto_manager)?, x))
            .collect();
        Ok(IteratorListResponse {
            data: data?,
            done: response.done,
            iterator: response.iterator,
        })
    }

    /// Fetch the latest revision of the supplied [`Item`]s from the server and return an [`ItemListResponse`]
    ///
    /// # Arguments:
    /// * `items` - the list of UIDs for the items to be fetched
    /// * `options` - parameters to tune or optimize the fetch
    pub fn fetch_updates<'a, I>(
        &self,
        items: I,
        options: Option<&FetchOptions>,
    ) -> Result<ItemListResponse<Item>>
    where
        I: Iterator<Item = &'a Item>,
    {
        let items = items.map(|x| &x.item);
        let response = self.item_manager_online.fetch_updates(items, options)?;
        let data: Result<Vec<Item>> = response
            .data
            .into_iter()
            .map(|x| Item::new(x.crypto_manager(&self.collection_crypto_manager)?, x))
            .collect();
        Ok(ItemListResponse {
            data: data?,
            done: response.done,
            stoken: response.stoken,
        })
    }

    /// Fetch multiple [`Item`]s using their UID
    ///
    /// See [`fetch`](Self::fetch) for fetching a single item
    ///
    /// # Arguments:
    /// * `items` - the list of items to be fetched
    /// * `options` - parameters to tune or optimize the fetch
    pub fn fetch_multi<'a, I>(
        &self,
        items: I,
        options: Option<&FetchOptions>,
    ) -> Result<ItemListResponse<Item>>
    where
        I: Iterator<Item = &'a StrBase64>,
    {
        let response = self.item_manager_online.fetch_multi(items, options)?;
        let data: Result<Vec<Item>> = response
            .data
            .into_iter()
            .map(|x| Item::new(x.crypto_manager(&self.collection_crypto_manager)?, x))
            .collect();
        Ok(ItemListResponse {
            data: data?,
            done: response.done,
            stoken: response.stoken,
        })
    }

    /// Upload the supplied [`Item`]s to the server
    ///
    /// # Arguments:
    /// * `items` - the list of items to be uploaded
    /// * `options` - parameters to tune or optimize the upload
    pub fn batch<'a, I>(&self, items: I, options: Option<&FetchOptions>) -> Result<()>
    where
        I: Iterator<Item = &'a Item>,
    {
        let items = items.map(|x| &x.item);
        let deps = std::iter::empty();
        self.item_manager_online.batch(items, deps, options)
    }

    /// Upload the supplied [`Item`]s to the server with a list of items as dependencies
    ///
    /// This will fail if the dependencies have changed remotely
    ///
    /// # Arguments:
    /// * `items` - the list of items to be uploaded
    /// * `deps` - the list of items to be treated as dependencies
    /// * `options` - parameters to tune or optimize the upload
    pub fn batch_deps<'a, I, J>(
        &self,
        items: I,
        deps: J,
        options: Option<&FetchOptions>,
    ) -> Result<()>
    where
        I: Iterator<Item = &'a Item>,
        J: Iterator<Item = &'a Item>,
    {
        let items = items.map(|x| &x.item);
        let deps = deps.map(|x| &x.item);
        self.item_manager_online.batch(items, deps, options)
    }

    /// Upload an [`Item`] using a transaction
    ///
    /// This call ensures that the item hasn't changed since we last fetched it
    ///
    /// # Arguments:
    /// * `items` - the list of items to be uploaded
    /// * `options` - parameters to tune or optimize the upload
    pub fn transaction<'a, I>(&self, items: I, options: Option<&FetchOptions>) -> Result<()>
    where
        I: Iterator<Item = &'a Item>,
    {
        let items = items.map(|x| &x.item);
        let deps = std::iter::empty();
        self.item_manager_online.transaction(items, deps, options)
    }

    /// Create an upload transaction for the supplied [`Item`]s with a list of items as dependencies
    ///
    /// This will fail if the dependencies have changed remotely
    ///
    /// # Arguments:
    /// * `items` - the list of items to be uploaded
    /// * `deps` - the list of items to be treated as dependencies
    /// * `options` - parameters to tune or optimize the upload
    pub fn transaction_deps<'a, I, J>(
        &self,
        items: I,
        deps: J,
        options: Option<&FetchOptions>,
    ) -> Result<()>
    where
        I: Iterator<Item = &'a Item>,
        J: Iterator<Item = &'a Item>,
    {
        let items = items.map(|x| &x.item);
        let deps = deps.map(|x| &x.item);
        self.item_manager_online.transaction(items, deps, options)
    }

    /// Pre-upload the item's content - use it with large files
    ///
    /// Pre-uploading item content is recommended when dealing with large files as it's much more
    /// efficient. It uploads the content of the item in advance so you don't need to upload it as
    /// part of transactions.
    ///
    /// # Arguments:
    /// * `item` - the item to upload
    pub fn upload_content(&self, item: &Item) -> Result<()> {
        let item = &item.item;
        for chunk in item.pending_chunks() {
            match self.item_manager_online.chunk_upload(item, chunk, None) {
                Err(Error::Conflict(_)) => (),
                Err(err) => return Err(err),
                _ => (),
            };
        }

        Ok(())
    }

    /// Download the content of an item if missing
    ///
    /// When using some [`FetchOptions`] items may be incomplete. Use this call to download the
    /// item's content so it can be accessed.
    /// This is a much more efficient way of getting the content of large files.
    ///
    /// # Arguments:
    /// * `item` - the item to upload
    pub fn download_content(&self, item: &mut Item) -> Result<()> {
        // FIXME: unnecessary copy
        let item_uid = item.uid().to_owned();
        let item = &mut item.item;
        for chunk in item.missing_chunks() {
            chunk.1 = Some(
                self.item_manager_online
                    .chunk_download(&item_uid, &chunk.0, None)?,
            );
        }

        Ok(())
    }

    /// Load and return a cached [`Item`] object from a byte buffer obtained using
    /// [`cache_save`](Self::cache_save)
    ///
    /// # Arguments:
    /// * `cached` - the byte buffer holding the cached item
    pub fn cache_load(&self, cached: &[u8]) -> Result<Item> {
        let item = EncryptedItem::cache_load(cached)?;
        Item::new(item.crypto_manager(&self.collection_crypto_manager)?, item)
    }

    /// Save the [`Item`] object to a byte buffer for caching
    ///
    /// The item can later be loaded using [`cache_load`](Self::cache_load)
    ///
    /// # Arguments:
    /// * `item` - the item object to be cached
    pub fn cache_save(&self, item: &Item) -> Result<Vec<u8>> {
        item.item.cache_save()
    }

    /// Save the [`Item`] object and its content to a byte buffer for caching
    ///
    /// The item can later be loaded using [`cache_load`](Self::cache_load)
    ///
    /// # Arguments:
    /// * `item` - the item object to be cached
    pub fn cache_save_with_content(&self, item: &Item) -> Result<Vec<u8>> {
        item.item.cache_save_with_content()
    }
}

/// An manager for managing user invitations to collections
pub struct CollectionInvitationManager {
    account_crypto_manager: Arc<AccountCryptoManager>,
    identity_crypto_manager: BoxCryptoManager,
    invitation_manager_online: CollectionInvitationManagerOnline,
}

impl CollectionInvitationManager {
    fn new(
        client: Arc<Client>,
        account_crypto_manager: Arc<AccountCryptoManager>,
        identity_crypto_manager: BoxCryptoManager,
    ) -> Result<Self> {
        let invitation_manager_online = CollectionInvitationManagerOnline::new(Arc::clone(&client));
        Ok(Self {
            account_crypto_manager,
            identity_crypto_manager,
            invitation_manager_online,
        })
    }

    /// List the incoming collection invitations for the account
    ///
    /// # Arguments:
    /// * `options` - the [`FetchOptions`] to fetch with
    pub fn list_incoming(
        &self,
        options: Option<&FetchOptions>,
    ) -> Result<IteratorListResponse<SignedInvitation>> {
        self.invitation_manager_online.list_incoming(options)
    }

    /// List the outgoing collection invitations for the account
    ///
    /// # Arguments:
    /// * `options` - the [`FetchOptions`] to fetch with
    pub fn list_outgoing(
        &self,
        options: Option<&FetchOptions>,
    ) -> Result<IteratorListResponse<SignedInvitation>> {
        self.invitation_manager_online.list_outgoing(options)
    }

    /// Accept an invitation
    ///
    /// # Arguments:
    /// * `invitation` - the invitation to accept
    pub fn accept(&self, invitation: &SignedInvitation) -> Result<()> {
        let raw_content =
            buffer_unpad(&invitation.decrypted_encryption_key(&self.identity_crypto_manager)?)?;
        let content: SignedInvitationContent = rmp_serde::from_slice(&raw_content)?;
        let collection_type_uid = self
            .account_crypto_manager
            .collection_type_to_uid(&content.collection_type)?;
        let encryption_key = &self
            .account_crypto_manager
            .0
            .encrypt(&content.encryption_key, Some(&collection_type_uid))?;
        self.invitation_manager_online
            .accept(invitation, &collection_type_uid, encryption_key)
    }

    /// Reject an invitation
    ///
    /// # Arguments:
    /// * `invitation` - the invitation to reject
    pub fn reject(&self, invitation: &SignedInvitation) -> Result<()> {
        self.invitation_manager_online.reject(invitation)
    }

    /// Fetch and return a user's profile
    ///
    /// # Arguments:
    /// * `username` - the username of the user to fetch
    pub fn fetch_user_profile(&self, username: &str) -> Result<UserProfile> {
        self.invitation_manager_online.fetch_user_profile(username)
    }

    /// Invite a user to a collection
    ///
    /// # Arguments:
    /// * `collection` - the collection to invite to
    /// * `username` - the username of the user to invite
    /// * `pubkey` - the public key of the user to invite
    /// * `access_level` - the level of access to give to user
    pub fn invite(
        &self,
        collection: &Collection,
        username: &str,
        pubkey: &[u8],
        access_level: CollectionAccessLevel,
    ) -> Result<()> {
        let pubkey: &[u8; 32] = pubkey
            .try_into()
            .map_err(|_| Error::ProgrammingError("Public key should be exactly 32 bytes long"))?;
        let invitation = collection.col.create_invitation(
            &self.account_crypto_manager,
            &self.identity_crypto_manager,
            username,
            pubkey,
            access_level,
        )?;
        self.invitation_manager_online.invite(&invitation)
    }

    /// Cancel an invitation (disinvite)
    ///
    /// # Arguments:
    /// * `invitation` - the invitation to cancel
    pub fn disinvite(&self, invitation: &SignedInvitation) -> Result<()> {
        self.invitation_manager_online.disinvite(invitation)
    }

    /// Our identity's public key
    ///
    /// This is the key users see when we send invitations.
    /// Can be pretty printed with [`pretty_fingerprint`](crate::pretty_fingerprint).
    pub fn pubkey(&self) -> &[u8] {
        self.identity_crypto_manager.pubkey()
    }
}

/// An manager for managing the members of a collection
pub struct CollectionMemberManager {
    member_manager_online: CollectionMemberManagerOnline,
}

impl CollectionMemberManager {
    fn new(client: Arc<Client>, collection: &Collection) -> Result<Self> {
        let member_manager_online =
            CollectionMemberManagerOnline::new(Arc::clone(&client), &collection.col);
        Ok(Self {
            member_manager_online,
        })
    }

    /// List the members of a collection
    ///
    /// # Arguments:
    /// * `options` - the [`FetchOptions`] to fetch with
    pub fn list(
        &self,
        options: Option<&FetchOptions>,
    ) -> Result<IteratorListResponse<CollectionMember>> {
        self.member_manager_online.list(options)
    }

    /// Remove a member from the collection
    ///
    /// # Arguments:
    /// * `username` - the member's username
    pub fn remove(&self, username: &str) -> Result<()> {
        self.member_manager_online.remove(username)
    }

    /// Leave a collection the user is a member of
    pub fn leave(&self) -> Result<()> {
        self.member_manager_online.leave()
    }

    /// Modify the access level of a member
    ///
    /// # Arguments:
    /// * `username` - the member's username
    /// * `access_level` - the new [`CollectionAccessLevel`]
    pub fn modify_access_level(
        &self,
        username: &str,
        access_level: CollectionAccessLevel,
    ) -> Result<()> {
        self.member_manager_online
            .modify_access_level(username, access_level)
    }
}

/// A collection of items
///
/// Like [`Item`]s, collections have two pieces of data associated with them:
/// * [metadata](ItemMetadata) - contains meta information like name and modification time
/// * Content - a buffer containing arbitrary binary data
/// They also have an immutable type and an associated sync token
#[derive(Clone)]
pub struct Collection {
    col: EncryptedCollection,
    cm: Arc<CollectionCryptoManager>,
    account_crypto_manager: Arc<AccountCryptoManager>,
}

impl Collection {
    fn new(
        account_crypto_manager: Arc<AccountCryptoManager>,
        crypto_manager: CollectionCryptoManager,
        encrypted_collection: EncryptedCollection,
    ) -> Result<Self> {
        Ok(Self {
            col: encrypted_collection,
            cm: Arc::new(crypto_manager),
            account_crypto_manager,
        })
    }

    /// Manually verify the integrity of the collection
    ///
    /// This is also done automatically by the API
    pub fn verify(&self) -> Result<bool> {
        self.col.verify(&self.cm)
    }

    /// Set metadata for the collection object
    ///
    /// # Arguments:
    /// * `meta` - the [`ItemMetadata`] object to be set for the collection
    pub fn set_meta<T: MsgPackSerilization>(&mut self, meta: &T) -> Result<()> {
        let meta = meta.to_msgpack()?;
        self.col.set_meta(&self.cm, &meta)
    }

    /// Return the [`ItemMetadata`] of the collection
    pub fn meta(&self) -> Result<ItemMetadata> {
        self.meta_generic::<ItemMetadata>()
    }

    /// Return the [`ItemMetadata`] of the collection deserializing using a generic metadata object
    ///
    /// The metadata object needs to implement the [`MsgPackSerilization`] trait.
    pub fn meta_generic<T: MsgPackSerilization>(&self) -> Result<T::Output> {
        let decrypted = self.col.meta(&self.cm)?;
        T::from_msgpack(&decrypted)
    }

    /// Set metadata for the collection object from a byte array
    ///
    /// # Arguments:
    /// * `meta` - the metadata for the collection. This needs to be a valid [`ItemMetadata`] struct encoded using `msgpack`.
    pub fn set_meta_raw(&mut self, meta: &[u8]) -> Result<()> {
        self.col.set_meta(&self.cm, meta)
    }

    /// Return metadata for the collection object as a byte array
    pub fn meta_raw(&self) -> Result<Vec<u8>> {
        self.col.meta(&self.cm)
    }

    /// Set the content of the collection
    ///
    /// # Arguments:
    /// * `content` - the content of the collection as a byte array
    pub fn set_content(&mut self, content: &[u8]) -> Result<()> {
        self.col.set_content(&self.cm, content)
    }

    /// Return the content of the collection as a byte array
    pub fn content(&self) -> Result<Vec<u8>> {
        self.col.content(&self.cm)
    }

    /// Mark the collection as deleted
    ///
    /// The collection needs to be [uploaded](CollectionManager::upload) for this to take effect
    pub fn delete(&mut self) -> Result<()> {
        self.col.delete(&self.cm)
    }

    /// Check whether the collection is marked as deleted
    pub fn is_deleted(&self) -> bool {
        self.col.is_deleted()
    }

    /// The UID of the collection
    pub fn uid(&self) -> &str {
        self.col.uid()
    }

    /// The etag of the collection
    pub fn etag(&self) -> &str {
        self.col.etag()
    }

    /// The sync token for the collection
    ///
    /// The sync token reflects changes to the collection properties or its [`Item`]s on the server
    pub fn stoken(&self) -> Option<&str> {
        self.col.stoken()
    }

    /// Return the access level of the collection for the current user
    pub fn access_level(&self) -> CollectionAccessLevel {
        self.col.access_level()
    }

    /// Return the collection as an [`Item`]
    pub fn item(&self) -> Result<Item> {
        let encrypted_item = self.col.item();
        let crypto_manager = encrypted_item.crypto_manager(&self.cm)?;
        Item::new(crypto_manager, encrypted_item.clone())
    }

    /// The type of the collection
    pub fn collection_type(&self) -> Result<String> {
        self.col.collection_type(&self.account_crypto_manager)
    }
}

/// Items belong to collections and are where data is stored
///
/// Items have two pieces of data associated with them:
/// * [metadata](ItemMetadata) - contains meta information like name and modification time
/// * Content - a buffer containing arbitrary binary data.
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

    /// Manually verify the integrity of the item
    ///
    /// This is usually done automatically by the API
    pub fn verify(&self) -> Result<bool> {
        self.item.verify(&self.cm)
    }

    /// Set metadata for the item object
    ///
    /// # Arguments:
    /// * `meta` - the [`ItemMetadata`] object to be set for the item
    pub fn set_meta<T: MsgPackSerilization>(&mut self, meta: &T) -> Result<()> {
        let meta = meta.to_msgpack()?;
        self.item.set_meta(&self.cm, &meta)
    }

    /// Return the [`ItemMetadata`] of the item
    pub fn meta(&self) -> Result<ItemMetadata> {
        self.meta_generic::<ItemMetadata>()
    }

    /// Return the [`ItemMetadata`] of the collection deserializing using a generic metadata object
    ///
    /// The metadata object needs to implement the [`MsgPackSerilization`] trait.
    pub fn meta_generic<T: MsgPackSerilization>(&self) -> Result<T::Output> {
        let decrypted = self.item.meta(&self.cm)?;
        T::from_msgpack(&decrypted)
    }

    /// Set metadata for the item object from a byte array
    ///
    /// # Arguments:
    /// * `meta` - the metadata for the item. This needs to be a valid [`ItemMetadata`] struct encoded using `msgpack`.
    pub fn set_meta_raw(&mut self, meta: &[u8]) -> Result<()> {
        self.item.set_meta(&self.cm, meta)
    }

    /// Return metadata for the item object as a byte array
    pub fn meta_raw(&self) -> Result<Vec<u8>> {
        self.item.meta(&self.cm)
    }

    /// Set the content of the item
    ///
    /// # Arguments:
    /// * `content` - the content of the item as a byte array
    pub fn set_content(&mut self, content: &[u8]) -> Result<()> {
        self.item.set_content(&self.cm, content)
    }

    /// Return the content of the item as a byte array
    pub fn content(&self) -> Result<Vec<u8>> {
        self.item.content(&self.cm)
    }

    /// Mark the item as deleted
    ///
    /// The item needs to be [uploaded](ItemManager::batch) for this to take effect
    pub fn delete(&mut self) -> Result<()> {
        self.item.delete(&self.cm)
    }

    /// Check whether the item is marked as deleted
    pub fn is_deleted(&self) -> bool {
        self.item.is_deleted()
    }

    /// Check whether the item is missing content and should be downloaded
    ///
    /// If it is, the content should be downloaded with [`ItemManager::download_content`].
    pub fn is_missing_content(&self) -> bool {
        self.item.is_missing_content()
    }

    /// The UID of the item
    pub fn uid(&self) -> &str {
        self.item.uid()
    }

    /// The etag of the item
    pub fn etag(&self) -> &str {
        self.item.etag()
    }
}

pub(crate) fn test_chunk_uids(item: &Item) -> Vec<String> {
    item.item.test_chunk_uids()
}
