// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate rmp_serde;

use std::cell::RefCell;
use std::convert::TryInto;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use sodiumoxide::crypto::sign;

use super::{
    chunker::Rollsum,
    crypto::{BoxCryptoManager, CryptoMac, CryptoManager},
    error::{Error, Result},
    try_into,
    utils::{
        buffer_pad, buffer_pad_fixed, buffer_pad_small, buffer_unpad, buffer_unpad_fixed,
        from_base64, memcmp, randombytes, shuffle, to_base64, MsgPackSerilization, StringBase64,
        SYMMETRIC_KEY_SIZE,
    },
    CURRENT_VERSION,
};

pub fn gen_uid_base64() -> StringBase64 {
    to_base64(&randombytes(24)).unwrap()
}

#[derive(Serialize, Deserialize)]
pub struct CachedContent {
    version: u8,
    data: Vec<u8>,
}

pub struct AccountCryptoManager(pub CryptoManager);

impl AccountCryptoManager {
    const COLTYPE_PAD_SIZE: usize = 32;

    pub fn new(key: &[u8; 32], version: u8) -> Result<Self> {
        let context = b"Acct    ";

        Ok(Self(CryptoManager::new(key, context, version)?))
    }

    pub fn collection_type_to_uid(&self, collection_type: &str) -> Result<Vec<u8>> {
        self.0.deterministic_encrypt(
            &buffer_pad_fixed(collection_type.as_bytes(), Self::COLTYPE_PAD_SIZE)?,
            None,
        )
    }

    pub fn collection_type_from_uid(&self, collection_type_uid: &[u8]) -> Result<String> {
        buffer_unpad_fixed(
            &self.0.deterministic_decrypt(collection_type_uid, None)?,
            Self::COLTYPE_PAD_SIZE,
        )
        .map(|x| String::from_utf8(x).unwrap_or_else(|_| "BAD TYPE".to_owned()))
    }
}

pub struct CollectionCryptoManager(CryptoManager);

impl CollectionCryptoManager {
    pub fn new(key: &[u8; 32], version: u8) -> Result<Self> {
        let context = b"Col     ";

        Ok(Self(CryptoManager::new(key, context, version)?))
    }
}

pub struct ItemCryptoManager(CryptoManager);

impl ItemCryptoManager {
    pub fn new(key: &[u8; 32], version: u8) -> Result<Self> {
        let context = b"ColItem ";

        Ok(Self(CryptoManager::new(key, context, version)?))
    }
}

/// Metadata of the item
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ItemMetadata {
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtime: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    color: Option<String>,
}

impl ItemMetadata {
    /// Create a new metadata object
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the item type
    ///
    /// # Arguments:
    /// * `type` - the type to be set
    pub fn set_item_type(&mut self, type_: Option<impl Into<String>>) -> &mut Self {
        self.type_ = type_.map(|x| x.into());
        self
    }

    /// The item type
    pub fn item_type(&self) -> Option<&str> {
        self.type_.as_deref()
    }

    /// Set the item name
    ///
    /// For example, you can set it to "Secret Note" or "todo.txt"
    ///
    /// # Arguments:
    /// * `name` - the name to be set
    pub fn set_name(&mut self, name: Option<impl Into<String>>) -> &mut Self {
        self.name = name.map(|x| x.into());
        self
    }

    /// The item name
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Set the modification time of the item
    ///
    /// # Arguments:
    /// * `mtime` - the modification time in milliseconds since epoch
    pub fn set_mtime(&mut self, mtime: Option<i64>) -> &mut Self {
        self.mtime = mtime;
        self
    }

    /// Modification time of the item
    pub fn mtime(&self) -> Option<i64> {
        self.mtime
    }

    /// Set a description for the item
    ///
    /// # Arguments:
    /// * `description` - the description to be set
    pub fn set_description(&mut self, description: Option<impl Into<String>>) -> &mut Self {
        self.description = description.map(|x| x.into());
        self
    }

    /// The item description
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Set a color for the item
    ///
    /// # Arguments:
    /// * `color` - the color to be set in `#RRGGBB` or `#RRGGBBAA` format
    pub fn set_color(&mut self, color: Option<impl Into<String>>) -> &mut Self {
        self.color = color.map(|x| x.into());
        self
    }

    /// The item color in `#RRGGBB` or `#RRGGBBAA` format
    pub fn color(&self) -> Option<&str> {
        self.color.as_deref()
    }
}

impl MsgPackSerilization for ItemMetadata {
    type Output = ItemMetadata;

    fn to_msgpack(&self) -> Result<Vec<u8>> {
        Ok(rmp_serde::to_vec_named(self)?)
    }

    fn from_msgpack(data: &[u8]) -> Result<Self::Output> {
        Ok(rmp_serde::from_read_ref(data)?)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignedInvitationContent {
    #[serde(with = "serde_bytes")]
    pub encryption_key: Vec<u8>,
    pub collection_type: String,
}

/// A signed invitation to join a collection
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedInvitation {
    uid: StringBase64,
    version: u8,
    username: String,

    collection: String,
    access_level: CollectionAccessLevel,

    #[serde(with = "serde_bytes")]
    signed_encryption_key: Vec<u8>,

    from_username: Option<String>,

    #[serde(with = "serde_bytes", skip_serializing)]
    from_pubkey: Option<Vec<u8>>,
}

impl SignedInvitation {
    /// The uid of the invitation
    pub fn uid(&self) -> &str {
        &self.uid
    }

    /// The username this invitation is for
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The collection uid of the [`Collection`](crate::Collection) this invitation is for
    pub fn collection(&self) -> &str {
        &self.collection
    }

    /// The access level offered in this invitation
    pub fn access_level(&self) -> CollectionAccessLevel {
        self.access_level
    }

    /// The username of the inviting user
    pub fn sender_username(&self) -> Option<&str> {
        self.from_username.as_deref()
    }

    /// The public key of the inviting user
    pub fn sender_pubkey(&self) -> &[u8] {
        match self.from_pubkey.as_deref() {
            Some(from_pubkey) => from_pubkey,
            None => panic!("Can never happen. Tried getting empty pubkey."),
        }
    }

    #[deprecated = "This method has been renamed to sender_username() to avoid potential confusion regarding its name"]
    pub fn from_username(&self) -> Option<&str> {
        self.sender_username()
    }

    #[deprecated = "This method has been renamed to sender_pubkey() to avoid potential confusion regarding its name"]
    pub fn from_pubkey(&self) -> &[u8] {
        self.sender_pubkey()
    }

    pub(crate) fn decrypted_encryption_key(
        &self,
        identity_crypto_manager: &BoxCryptoManager,
    ) -> Result<Vec<u8>> {
        let from_pubkey = match self.from_pubkey.as_deref() {
            Some(from_pubkey) => from_pubkey,
            None => {
                return Err(Error::ProgrammingError(
                    "Missing invitation encryption key.",
                ))
            }
        };
        identity_crypto_manager.decrypt(&self.signed_encryption_key, try_into!(from_pubkey)?)
    }
}

/// The access level to a collection
#[derive(Serialize_repr, Deserialize_repr, Clone, Copy, PartialEq, Debug)]
#[repr(u32)]
pub enum CollectionAccessLevel {
    /// Read only access
    ReadOnly,
    /// Admin access
    Admin,
    /// Read and write access
    ReadWrite,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedCollection {
    // Order matters because that's how we save to cache
    item: EncryptedItem,
    access_level: CollectionAccessLevel,
    #[serde(with = "serde_bytes")]
    collection_key: Vec<u8>,
    // FIXME: remove the option "collection-type-migration" is done
    #[serde(with = "serde_bytes")]
    collection_type: Option<Vec<u8>>,
    stoken: Option<String>,
}

impl EncryptedCollection {
    pub fn new(
        parent_crypto_manager: &AccountCryptoManager,
        collection_type: &str,
        meta: &[u8],
        content: &[u8],
    ) -> Result<Self> {
        let version = CURRENT_VERSION;
        let collection_type = parent_crypto_manager.collection_type_to_uid(collection_type)?;
        let collection_key = parent_crypto_manager
            .0
            .encrypt(&randombytes(SYMMETRIC_KEY_SIZE), Some(&collection_type))?;
        let crypto_manager = Self::crypto_manager_static(
            parent_crypto_manager,
            version,
            &collection_key,
            Some(&collection_type),
        )?;
        let item = EncryptedItem::new(&crypto_manager, meta, content)?;

        Ok(Self {
            item,
            access_level: CollectionAccessLevel::Admin,
            collection_key,
            collection_type: Some(collection_type),

            stoken: None,
        })
    }

    pub fn cache_load(cached: &[u8]) -> Result<Self> {
        let cached: CachedContent = rmp_serde::from_read_ref(cached)?;
        let ret: std::result::Result<Self, _> = rmp_serde::from_read_ref(&cached.data);
        // FIXME: remove this whole match once "collection-type-migration" is done
        Ok(match ret {
            Ok(ret) => ret,
            Err(_) => {
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct EncryptedCollectionLegacy {
                    item: EncryptedItem,
                    access_level: CollectionAccessLevel,
                    #[serde(with = "serde_bytes")]
                    collection_key: Vec<u8>,
                    stoken: Option<String>,
                }

                let ret: EncryptedCollectionLegacy = rmp_serde::from_read_ref(&cached.data)?;

                Self {
                    item: ret.item,
                    access_level: ret.access_level,
                    collection_key: ret.collection_key,
                    stoken: ret.stoken,
                    collection_type: None,
                }
            }
        })
    }

    // FIXME: Actually make it not save content
    pub fn cache_save(&self) -> Result<Vec<u8>> {
        let data = rmp_serde::to_vec(self)?;
        let content = CachedContent {
            version: 1, // Cache version format
            data,
        };
        Ok(rmp_serde::to_vec(&content)?)
    }

    pub fn cache_save_with_content(&self) -> Result<Vec<u8>> {
        let data = rmp_serde::to_vec(self)?;
        let content = CachedContent {
            version: 1, // Cache version format
            data,
        };
        Ok(rmp_serde::to_vec(&content)?)
    }

    pub(crate) fn mark_saved(&self) {
        self.item.mark_saved();
    }

    pub fn verify(&self, crypto_manager: &CollectionCryptoManager) -> Result<bool> {
        let item_crypto_manager = self.item.crypto_manager(crypto_manager)?;
        self.item.verify(&item_crypto_manager)
    }

    pub fn set_meta(
        &mut self,
        crypto_manager: &CollectionCryptoManager,
        meta: &[u8],
    ) -> Result<()> {
        let item_crypto_manager = self.item.crypto_manager(crypto_manager)?;
        self.item.set_meta(&item_crypto_manager, meta)
    }

    pub fn meta(&self, crypto_manager: &CollectionCryptoManager) -> Result<Vec<u8>> {
        self.verify(crypto_manager)?;
        let item_crypto_manager = self.item.crypto_manager(crypto_manager)?;
        self.item.meta(&item_crypto_manager)
    }

    pub fn set_content(
        &mut self,
        crypto_manager: &CollectionCryptoManager,
        content: &[u8],
    ) -> Result<()> {
        let item_crypto_manager = self.item.crypto_manager(crypto_manager)?;
        self.item.set_content(&item_crypto_manager, content)
    }

    pub fn content(&self, crypto_manager: &CollectionCryptoManager) -> Result<Vec<u8>> {
        self.verify(crypto_manager)?;
        let item_crypto_manager = self.item.crypto_manager(crypto_manager)?;
        self.item.content(&item_crypto_manager)
    }

    pub fn delete(&mut self, crypto_manager: &CollectionCryptoManager) -> Result<()> {
        let item_crypto_manager = self.item.crypto_manager(crypto_manager)?;
        self.item.delete(&item_crypto_manager)
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

    pub fn _is_new(&self) -> bool {
        self.item.etag.borrow().is_none()
    }

    pub fn stoken(&self) -> Option<&str> {
        self.stoken.as_deref()
    }

    pub fn access_level(&self) -> CollectionAccessLevel {
        self.access_level
    }

    pub fn item(&self) -> &EncryptedItem {
        &self.item
    }

    pub fn collection_type(&self, account_crypto_manager: &AccountCryptoManager) -> Result<String> {
        match &self.collection_type {
            Some(collection_type) => {
                account_crypto_manager.collection_type_from_uid(collection_type)
            }
            None => {
                let crypto_manager = self.crypto_manager(account_crypto_manager)?;
                let meta_raw = self.meta(&crypto_manager)?;
                Ok(ItemMetadata::from_msgpack(&meta_raw)?
                    .item_type()
                    .unwrap_or("BAD TYPE")
                    .to_owned())
            }
        }
    }

    pub fn create_invitation(
        &self,
        account_crypto_manager: &AccountCryptoManager,
        identity_crypto_manager: &BoxCryptoManager,
        username: &str,
        pubkey: &[u8; sign::PUBLICKEYBYTES],
        access_level: CollectionAccessLevel,
    ) -> Result<SignedInvitation> {
        let uid = to_base64(&randombytes(32))?;
        let encryption_key = self.collection_key(account_crypto_manager)?;
        let collection_type = self.collection_type(account_crypto_manager)?;
        let content = SignedInvitationContent {
            encryption_key,
            collection_type,
        };
        let raw_content = rmp_serde::to_vec_named(&content)?;
        let signed_encryption_key =
            identity_crypto_manager.encrypt(&buffer_pad_small(&raw_content)?, pubkey)?;
        Ok(SignedInvitation {
            uid,
            version: CURRENT_VERSION,
            username: username.to_owned(),
            collection: self.uid().to_owned(),
            access_level: access_level.to_owned(),

            signed_encryption_key,
            from_username: None,
            from_pubkey: Some(identity_crypto_manager.pubkey().to_owned()),
        })
    }

    fn collection_key_static(
        account_crypto_manager: &AccountCryptoManager,
        encryption_key: &[u8],
        collection_type: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        account_crypto_manager
            .0
            .decrypt(encryption_key, collection_type)
    }

    fn collection_key(&self, account_crypto_manager: &AccountCryptoManager) -> Result<Vec<u8>> {
        Self::collection_key_static(
            account_crypto_manager,
            &self.collection_key,
            self.collection_type.as_deref(),
        )
    }

    fn crypto_manager_static(
        parent_crypto_manager: &AccountCryptoManager,
        version: u8,
        encryption_key: &[u8],
        collection_type: Option<&[u8]>,
    ) -> Result<CollectionCryptoManager> {
        let encryption_key =
            Self::collection_key_static(parent_crypto_manager, encryption_key, collection_type)?;

        CollectionCryptoManager::new(try_into!(&encryption_key[..])?, version)
    }

    pub fn crypto_manager(
        &self,
        parent_crypto_manager: &AccountCryptoManager,
    ) -> Result<CollectionCryptoManager> {
        Self::crypto_manager_static(
            parent_crypto_manager,
            self.item.version,
            &self.collection_key,
            self.collection_type.as_deref(),
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct ChunkArrayItem(
    pub StringBase64,
    #[serde(default)]
    #[serde(with = "serde_bytes")]
    pub Option<Vec<u8>>,
);

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedRevision {
    uid: StringBase64,
    #[serde(with = "serde_bytes")]
    meta: Vec<u8>,
    deleted: bool,

    chunks: Vec<ChunkArrayItem>,
}

impl EncryptedRevision {
    pub fn new(
        crypto_manager: &ItemCryptoManager,
        additional_data: &[u8],
        meta: &[u8],
        content: &[u8],
    ) -> Result<Self> {
        let mut ret = Self {
            uid: "".to_owned(),
            meta: vec![],
            deleted: false,

            chunks: vec![],
        };

        ret.set_meta(crypto_manager, additional_data, meta)?;
        ret.set_content(crypto_manager, additional_data, content)?;

        Ok(ret)
    }

    fn calculate_hash(
        &self,
        crypto_manager: &ItemCryptoManager,
        additional_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut crypto_mac = crypto_manager.0.crypto_mac()?;
        crypto_mac.update(&[self.deleted as u8])?;
        crypto_mac.update_with_len_prefix(additional_data)?;

        // We hash the chunks separately so that the server can (in the future) return just the hash instead of the full
        // chunk list if requested - useful for asking for collection updates
        let mut chunks_hash = CryptoMac::new(None)?;
        for chunk in self.chunks.iter() {
            chunks_hash.update(&from_base64(&chunk.0)?)?;
        }

        crypto_mac.update(&chunks_hash.finalize()?)?;

        crypto_mac.finalize()
    }

    pub fn verify(
        &self,
        crypto_manager: &ItemCryptoManager,
        additional_data: &[u8],
    ) -> Result<bool> {
        let mac = from_base64(&self.uid)?;
        let ad_hash = self.calculate_hash(crypto_manager, additional_data)?;

        crypto_manager
            .0
            .verify(&self.meta, try_into!(&mac[..])?, Some(&ad_hash))
    }

    pub fn set_meta(
        &mut self,
        crypto_manager: &ItemCryptoManager,
        additional_data: &[u8],
        meta: &[u8],
    ) -> Result<()> {
        let ad_hash = self.calculate_hash(crypto_manager, additional_data)?;

        let msg = buffer_pad_small(meta)?;
        let enc_content = crypto_manager.0.encrypt_detached(&msg, Some(&ad_hash))?;

        self.uid = to_base64(&enc_content.0)?;
        self.meta = enc_content.1;

        Ok(())
    }

    pub fn meta(
        &self,
        crypto_manager: &ItemCryptoManager,
        additional_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mac = from_base64(&self.uid)?;
        let ad_hash = self.calculate_hash(crypto_manager, additional_data)?;

        buffer_unpad(&crypto_manager.0.decrypt_detached(
            &self.meta,
            try_into!(&mac[..])?,
            Some(&ad_hash),
        )?)
    }

    pub fn set_content(
        &mut self,
        crypto_manager: &ItemCryptoManager,
        additional_data: &[u8],
        content: &[u8],
    ) -> Result<()> {
        let meta = self.meta(crypto_manager, additional_data)?;

        let mut chunks: Vec<ChunkArrayItem> = vec![];

        let min_chunk = 1 << 14;
        let max_chunk = 1 << 16;
        let mut chunk_start = 0;

        let content_length = content.len();
        if content_length > min_chunk {
            // FIXME: figure out what to do with mask - should it be configurable?
            let mask = (1 << 12) - 1;
            let mut chunker = Rollsum::new();
            let mut pos = 0;
            while pos < content_length {
                chunker.update(content[pos]);
                let offset = pos - chunk_start;
                if offset >= min_chunk && ((offset >= max_chunk) || chunker.split(mask)) {
                    let buf = &content[chunk_start..pos];
                    let hash = to_base64(&crypto_manager.0.calculate_mac(buf)?)?;
                    chunks.push(ChunkArrayItem(hash, Some(buf.to_vec())));
                    chunk_start = pos;
                }
                pos += 1;
            }
        }

        if chunk_start < content.len() {
            let buf = &content[chunk_start..];
            let hash = to_base64(&crypto_manager.0.calculate_mac(buf)?)?;
            chunks.push(ChunkArrayItem(hash, Some(buf.to_vec())));
        }

        // Shuffle the items and save the ordering if we have more than one
        if !chunks.is_empty() {
            let mut indices = shuffle(&mut chunks);

            // Filter duplicates and construct the indice list.
            let mut uid_indices: HashMap<String, usize> = HashMap::new();
            chunks = chunks
                .into_iter()
                .enumerate()
                .filter_map(|(i, chunk)| {
                    let uid = &chunk.0;
                    match uid_indices.get(uid) {
                        Some(previous_index) => {
                            indices[i] = *previous_index;
                            None
                        }
                        None => {
                            uid_indices.insert(uid.to_string(), i);
                            Some(chunk)
                        }
                    }
                })
                .collect();

            // If we have more than one chunk we need to encode the mapping header in the last chunk
            if indices.len() > 1 {
                // We encode it in an array so we can extend it later on if needed
                let buf = rmp_serde::to_vec_named(&(indices,))?;
                let hash = to_base64(&crypto_manager.0.calculate_mac(&buf)?)?;
                chunks.push(ChunkArrayItem(hash, Some(buf)));
            }
        }

        let encrypt_item = |item: ChunkArrayItem| -> Result<ChunkArrayItem> {
            let hash = item.0;
            let buf = item.1;
            let ret = match buf {
                Some(buf) => Some(crypto_manager.0.encrypt(&buffer_pad(&buf)?, None)?),
                None => None,
            };

            Ok(ChunkArrayItem(hash, ret))
        };

        // Encrypt all of the chunks
        let encrypted_chunks: Result<Vec<_>> = chunks.into_iter().map(encrypt_item).collect();

        self.chunks = encrypted_chunks?;
        self.set_meta(crypto_manager, additional_data, &meta)?;

        Ok(())
    }

    pub fn content(&self, crypto_manager: &ItemCryptoManager) -> Result<Vec<u8>> {
        let mut indices = None;
        let item = |item: &ChunkArrayItem| -> Result<Vec<u8>> {
            let hash_str = &item.0;
            let buf = &item.1;
            let buf = match buf {
                Some(buf) => buffer_unpad(&crypto_manager.0.decrypt(buf, None)?)?,
                None => return Err(Error::MissingContent("Got chunk without data")),
            };

            let hash = from_base64(hash_str)?;
            let calculated_mac = crypto_manager.0.calculate_mac(&buf)?;

            if !memcmp(&hash, &calculated_mac) {
                return Err(Error::Encryption("Got a wrong mac for chunk"));
            }

            Ok(buf)
        };

        let decrypted_chunks: Result<Vec<_>> = self.chunks.iter().map(item).collect();
        let mut decrypted_chunks = decrypted_chunks?;

        // If we have more than one chunk we have the mapping header in the last chunk
        if self.chunks.len() > 1 {
            let buf = decrypted_chunks.pop().unwrap();
            let header_chunk: (Vec<usize>,) = rmp_serde::from_read_ref(&buf)?;
            indices = Some(header_chunk.0);
        }

        match indices {
            Some(indices) => {
                if indices.len() > 1 {
                    let sorted_chunks: Vec<u8> = indices
                        .into_iter()
                        .flat_map(|index| &decrypted_chunks[index])
                        // FIXME: We shouldn't copy but rather just move from the array
                        .copied()
                        .collect::<Vec<u8>>();

                    Ok(sorted_chunks)
                } else {
                    Ok(decrypted_chunks.into_iter().next().unwrap_or_default())
                }
            }
            None => Ok(decrypted_chunks.into_iter().next().unwrap_or_default()),
        }
    }

    pub fn delete(
        &mut self,
        crypto_manager: &ItemCryptoManager,
        additional_data: &[u8],
    ) -> Result<()> {
        let meta = self.meta(crypto_manager, additional_data)?;

        self.deleted = true;

        self.set_meta(crypto_manager, additional_data, &meta)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedItem {
    uid: StringBase64,
    version: u8,

    #[serde(with = "serde_bytes")]
    encryption_key: Option<Vec<u8>>,
    content: EncryptedRevision,

    etag: RefCell<Option<String>>,
}

impl EncryptedItem {
    pub fn new(
        parent_crypto_manager: &CollectionCryptoManager,
        meta: &[u8],
        content: &[u8],
    ) -> Result<Self> {
        let uid = gen_uid_base64();
        let version = CURRENT_VERSION;
        let crypto_manager =
            Self::crypto_manager_static(parent_crypto_manager, &uid, version, None)?;
        let content = EncryptedRevision::new(
            &crypto_manager,
            Self::additional_mac_data_static(&uid),
            meta,
            content,
        )?;

        Ok(Self {
            uid,
            version,
            encryption_key: None,
            content,

            etag: RefCell::new(None),
        })
    }

    pub(crate) fn clone_with_revision(&self, revision: EncryptedRevision) -> Self {
        let ret = Self {
            uid: self.uid.to_string(),
            version: self.version,
            encryption_key: self.encryption_key.as_ref().map(|x| x.to_vec()),

            content: revision,

            etag: RefCell::new(None),
        };
        // We give revisions their old etag
        ret.mark_saved();

        ret
    }

    pub fn cache_load(cached: &[u8]) -> Result<Self> {
        let cached: CachedContent = rmp_serde::from_read_ref(cached)?;
        Ok(rmp_serde::from_read_ref(&cached.data)?)
    }

    // FIXME: Actually make it not save content
    pub fn cache_save(&self) -> Result<Vec<u8>> {
        let data = rmp_serde::to_vec(self)?;
        let content = CachedContent {
            version: 1, // Cache version format
            data,
        };
        Ok(rmp_serde::to_vec(&content)?)
    }

    pub fn cache_save_with_content(&self) -> Result<Vec<u8>> {
        let data = rmp_serde::to_vec(self)?;
        let content = CachedContent {
            version: 1, // Cache version format
            data,
        };
        Ok(rmp_serde::to_vec(&content)?)
    }

    pub(crate) fn mark_saved(&self) {
        *self.etag.borrow_mut() = Some(self.content.uid.clone());
    }

    pub fn is_locally_changed(&self) -> bool {
        match self.etag.borrow().as_deref() {
            Some(etag) => etag == self.content.uid,
            None => false,
        }
    }

    pub fn verify(&self, crypto_manager: &ItemCryptoManager) -> Result<bool> {
        self.content
            .verify(crypto_manager, self.additional_mac_data())
    }

    pub fn set_meta(&mut self, crypto_manager: &ItemCryptoManager, meta: &[u8]) -> Result<()> {
        let ad_mac_data = Self::additional_mac_data_static(&self.uid);
        if self.is_locally_changed() {
            self.content.set_meta(crypto_manager, ad_mac_data, meta)?;
        } else {
            let mut rev = self.content.clone();
            rev.set_meta(crypto_manager, ad_mac_data, meta)?;
            self.content = rev;
        };

        Ok(())
    }

    pub fn meta(&self, crypto_manager: &ItemCryptoManager) -> Result<Vec<u8>> {
        self.verify(crypto_manager)?;
        self.content
            .meta(crypto_manager, self.additional_mac_data())
    }

    pub fn set_content(
        &mut self,
        crypto_manager: &ItemCryptoManager,
        content: &[u8],
    ) -> Result<()> {
        let ad_mac_data = Self::additional_mac_data_static(&self.uid);
        if self.is_locally_changed() {
            self.content
                .set_content(crypto_manager, ad_mac_data, content)?;
        } else {
            let mut rev = self.content.clone();
            rev.set_content(crypto_manager, ad_mac_data, content)?;
            self.content = rev;
        };

        Ok(())
    }

    pub fn content(&self, crypto_manager: &ItemCryptoManager) -> Result<Vec<u8>> {
        self.verify(crypto_manager)?;
        self.content.content(crypto_manager)
    }

    pub fn delete(&mut self, crypto_manager: &ItemCryptoManager) -> Result<()> {
        let ad_mac_data = Self::additional_mac_data_static(&self.uid);
        if self.is_locally_changed() {
            self.content.delete(crypto_manager, ad_mac_data)?;
        } else {
            let mut rev = self.content.clone();
            rev.delete(crypto_manager, ad_mac_data)?;
            self.content = rev;
        };

        Ok(())
    }

    pub fn is_deleted(&self) -> bool {
        self.content.deleted
    }

    pub fn uid(&self) -> &str {
        &self.uid
    }

    pub fn etag(&self) -> &str {
        &self.content.uid
    }

    pub(crate) fn last_etag(&self) -> Option<String> {
        self.etag.borrow().to_owned()
    }

    fn crypto_manager_static(
        parent_crypto_manager: &CollectionCryptoManager,
        uid: &str,
        version: u8,
        encryption_key: Option<&[u8]>,
    ) -> Result<ItemCryptoManager> {
        let encryption_key = match encryption_key {
            Some(encryption_key) => parent_crypto_manager
                .0
                .decrypt(encryption_key, None)?
                .try_into()
                .map_err(|_| {
                    Error::ProgrammingError("Decrypted encryption key has wrong length")
                })?,
            None => parent_crypto_manager.0.derive_subkey(uid.as_bytes())?,
        };

        ItemCryptoManager::new(&encryption_key, version)
    }

    pub fn crypto_manager(
        &self,
        parent_crypto_manager: &CollectionCryptoManager,
    ) -> Result<ItemCryptoManager> {
        let encryption_key = self.encryption_key.as_deref();
        Self::crypto_manager_static(
            parent_crypto_manager,
            &self.uid,
            self.version,
            encryption_key,
        )
    }

    fn additional_mac_data_static(uid: &str) -> &[u8] {
        uid.as_bytes()
    }

    fn additional_mac_data(&self) -> &[u8] {
        Self::additional_mac_data_static(&self.uid)
    }

    pub(crate) fn pending_chunks(&self) -> impl Iterator<Item = &ChunkArrayItem> {
        self.content.chunks.iter()
    }

    pub(crate) fn missing_chunks(&mut self) -> impl Iterator<Item = &mut ChunkArrayItem> {
        self.content.chunks.iter_mut().filter(|x| x.1.is_none())
    }

    pub fn is_missing_content(&self) -> bool {
        self.content.chunks.iter().any(|x| x.1.is_none())
    }

    pub(crate) fn test_chunk_uids(&self) -> Vec<String> {
        self.content.chunks.iter().map(|x| x.0.clone()).collect()
    }
}
