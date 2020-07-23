// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate rmp_serde;

use std::cell::RefCell;
use std::convert::TryInto;

use std::collections::HashMap;

use serde::{Serialize, Deserialize};

use super::{
    try_into,
    CURRENT_VERSION,
    crypto::{
        CryptoManager,
        CryptoMac,
    },
    chunker::Rollsum,
    error::{
        Error,
        Result,
    },
    utils::{
        buffer_pad_meta,
        buffer_pad,
        buffer_unpad,
        shuffle,
        memcmp,
        randombytes,
        from_base64,
        to_base64,
        StringBase64,
        SYMMETRIC_KEY_SIZE,
    },
};

pub fn gen_uid_base64() -> StringBase64 {
  return to_base64(&randombytes(24)).unwrap();
}

pub struct AccountCryptoManager(CryptoManager);

impl AccountCryptoManager {
    pub fn new(key: &[u8; 32], version: u8) -> Result<Self> {
        let context = b"Acct    ";

        Ok(Self {
            0: CryptoManager::new(key, &context, version)?,
        })
    }
}

pub struct CollectionCryptoManager(CryptoManager);

impl CollectionCryptoManager {
    pub fn new(key: &[u8; 32], version: u8) -> Result<Self> {
        let context = b"Col     ";

        Ok(Self {
            0: CryptoManager::new(key, &context, version)?,
        })
    }
}

pub struct ItemCryptoManager(CryptoManager);

impl ItemCryptoManager {
    pub fn new(key: &[u8; 32], version: u8) -> Result<Self> {
        let context = b"ColItem ";

        Ok(Self {
            0: CryptoManager::new(key, &context, version)?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct CollectionMetadata {
    type_: String,
    name: String,
    description: Option<String>,
    color: Option<String>,
    mtime: Option<i64>,
    // FIXME: missing extra
}

impl CollectionMetadata {
    pub fn new(type_: &str, name: &str) -> Self {
        Self {
            type_: type_.to_string(),
            name: name.to_string(),
            description: None,
            color: None,
            mtime: None,
        }
    }

    pub fn set_type(mut self, type_: &str) -> Self {
        self.type_ = type_.to_string();
        self
    }

    pub fn get_type(&self) -> &str {
        &self.type_
    }

    pub fn set_name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn set_description(mut self, description: Option<&str>) -> Self {
        self.description = description.and_then(|x| Some(x.to_string()));
        self
    }

    pub fn get_description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn set_color(mut self, color: Option<&str>) -> Self {
        self.color = color.and_then(|x| Some(x.to_string()));
        self
    }

    pub fn get_color(&self) -> Option<&str> {
        self.color.as_deref()
    }

    pub fn set_mtime(mut self, mtime: Option<i64>) -> Self {
        self.mtime = mtime;
        self
    }

    pub fn get_mtime(&self) -> Option<i64> {
        self.mtime
    }
}
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ItemMetadata {
    type_: Option<String>,
    name: Option<String>,
    mtime: Option<i64>,
    // FIXME: missing extra
}

impl ItemMetadata {
    pub fn new() -> Self {
        Self {
            type_: None,
            name: None,
            mtime: None,
        }
    }

    pub fn set_type(mut self, type_: Option<&str>) -> Self {
        self.type_ = type_.and_then(|x| Some(x.to_string()));
        self
    }

    pub fn get_type(&self) -> Option<&str> {
        self.type_.as_deref()
    }

    pub fn set_name(mut self, name: Option<&str>) -> Self {
        self.name = name.and_then(|x| Some(x.to_string()));
        self
    }

    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn set_mtime(mut self, mtime: Option<i64>) -> Self {
        self.mtime = mtime;
        self
    }

    pub fn get_mtime(&self) -> Option<i64> {
        self.mtime
    }
}


#[derive(Serialize, Deserialize, Clone)]
#[serde(from = "String", into = "String")]
enum CollectionAccessLevel {
    #[serde(rename = "adm")]
    Admin,
    #[serde(rename = "rw")]
    ReadWrite,
    #[serde(rename = "ro")]
    ReadOnly,
    Unknown(String),
}

impl From<String> for CollectionAccessLevel {
    fn from(input: String) -> Self {
        match &input[..] {
            "adm" => CollectionAccessLevel::Admin,
            "rw" => CollectionAccessLevel::ReadWrite,
            "ro" => CollectionAccessLevel::ReadOnly,
            unknown  => CollectionAccessLevel::Unknown(unknown.to_owned()),
        }
    }
}

impl From<CollectionAccessLevel> for String {
    fn from(input: CollectionAccessLevel) -> Self {
        match input {
            CollectionAccessLevel::Admin => "adm".to_owned(),
            CollectionAccessLevel::ReadWrite => "rw".to_owned(),
            CollectionAccessLevel::ReadOnly => "ro".to_owned(),
            CollectionAccessLevel::Unknown(string) => string.to_owned(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedCollection {
    item: EncryptedItem,
    access_level: CollectionAccessLevel,
    #[serde(with = "serde_bytes")]
    collection_key: Vec<u8>,
    stoken: Option<String>,
}

impl EncryptedCollection {
    pub fn new(parent_crypto_manager: &AccountCryptoManager, meta: &CollectionMetadata, content: &[u8]) -> Result<Self> {
        let version = CURRENT_VERSION;
        let collection_key = parent_crypto_manager.0.encrypt(&randombytes(SYMMETRIC_KEY_SIZE), None)?;
        let meta = rmp_serde::to_vec_named(meta)?;
        let crypto_manager = Self::get_crypto_manager_static(parent_crypto_manager, version, &collection_key)?;
        let item = EncryptedItem::new_raw(&crypto_manager, &meta, content)?;

        Ok(Self {
            item,
            access_level: CollectionAccessLevel::Admin,
            collection_key,

            stoken: None,
        })
    }

    pub(crate) fn mark_saved(&self) {
        self.item.mark_saved();
    }

    pub fn verify(&self, crypto_manager: &CollectionCryptoManager) -> Result<bool> {
        let item_crypto_manager = self.item.get_crypto_manager(crypto_manager)?;
        self.item.verify(&item_crypto_manager)
    }

    pub fn set_meta(&mut self, crypto_manager: &CollectionCryptoManager, meta: &[u8]) -> Result<()> {
        let item_crypto_manager = self.item.get_crypto_manager(crypto_manager)?;
        self.item.set_meta(&item_crypto_manager, &meta)
    }

    pub fn decrypt_meta(&self, crypto_manager: &CollectionCryptoManager) -> Result<Vec<u8>> {
        self.verify(crypto_manager)?;
        let item_crypto_manager = self.item.get_crypto_manager(crypto_manager)?;
        self.item.decrypt_meta(&item_crypto_manager)
    }

    pub fn set_content(&mut self, crypto_manager: &CollectionCryptoManager, content: &[u8]) -> Result<()> {
        let item_crypto_manager = self.item.get_crypto_manager(crypto_manager)?;
        self.item.set_content(&item_crypto_manager, content)
    }

    pub fn decrypt_content(&self, crypto_manager: &CollectionCryptoManager) -> Result<Vec<u8>> {
        self.verify(crypto_manager)?;
        let item_crypto_manager = self.item.get_crypto_manager(crypto_manager)?;
        self.item.decrypt_content(&item_crypto_manager)
    }

    pub fn delete(&mut self, crypto_manager: &CollectionCryptoManager) -> Result<()> {
        let item_crypto_manager = self.item.get_crypto_manager(crypto_manager)?;
        self.item.delete(&item_crypto_manager)
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

    pub fn get_stoken(&self) -> Option<&str> {
        self.stoken.as_deref()
    }

    pub fn get_item(&self) -> &EncryptedItem {
        &self.item
    }

    fn get_crypto_manager_static(parent_crypto_manager: &AccountCryptoManager, version: u8, encryption_key: &[u8]) -> Result<CollectionCryptoManager> {
        let encryption_key = parent_crypto_manager.0.decrypt(encryption_key, None)?;

        CollectionCryptoManager::new(try_into!(&encryption_key[..])?, version)
    }

    pub fn get_crypto_manager(&self, parent_crypto_manager: &AccountCryptoManager) -> Result<CollectionCryptoManager> {
        Self::get_crypto_manager_static(parent_crypto_manager, self.item.version, &self.collection_key)
    }
}


#[derive(Serialize, Deserialize, Clone)]
struct ChunkArrayItem(
    StringBase64,
    #[serde(with = "serde_bytes")]
    Option<Vec<u8>>,
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
    pub fn new(crypto_manager: &ItemCryptoManager, additional_data: &[u8], meta: &[u8], content: &[u8]) -> Result<Self> {
        let mut ret = Self {
            uid: "".to_owned(),
            meta: vec![],
            deleted: false,

            chunks: vec![],
        };

        ret.set_meta(&crypto_manager, additional_data, meta)?;
        ret.set_content(&crypto_manager, additional_data, content)?;

        Ok(ret)
    }

    fn calculate_hash(&self, crypto_manager: &ItemCryptoManager, additional_data: &[u8]) -> Result<Vec<u8>> {
        let mut crypto_mac = crypto_manager.0.get_crypto_mac()?;
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

    pub fn verify(&self, crypto_manager: &ItemCryptoManager, additional_data: &[u8]) -> Result<bool> {
        let mac = from_base64(&self.uid)?;
        let ad_hash = self.calculate_hash(crypto_manager, additional_data)?;

        crypto_manager.0.verify(&self.meta, try_into!(&mac[..])?, Some(&ad_hash))
    }

    pub fn set_meta(&mut self, crypto_manager: &ItemCryptoManager, additional_data: &[u8], meta: &[u8]) -> Result<()> {
        let ad_hash = self.calculate_hash(crypto_manager, additional_data)?;

        let msg = buffer_pad_meta(meta)?;
        let enc_content = crypto_manager.0.encrypt_detached(&msg, Some(&ad_hash))?;

        self.uid = to_base64(&enc_content.0)?;
        self.meta = enc_content.1;

        Ok(())
    }

    pub fn decrypt_meta(&self, crypto_manager: &ItemCryptoManager, additional_data: &[u8]) -> Result<Vec<u8>> {
        let mac = from_base64(&self.uid)?;
        let ad_hash = self.calculate_hash(crypto_manager, additional_data)?;

        buffer_unpad(&crypto_manager.0.decrypt_detached(&self.meta, try_into!(&mac[..])?, Some(&ad_hash))?)
    }

    pub fn set_content(&mut self, crypto_manager: &ItemCryptoManager, additional_data: &[u8], content: &[u8]) -> Result<()> {
        let meta = self.decrypt_meta(crypto_manager, additional_data)?;

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
                if offset >= min_chunk {
                    if (offset >= max_chunk) || chunker.split(mask) {
                        let buf = &content[chunk_start..pos];
                        let hash = to_base64(&crypto_manager.0.calculate_mac(buf)?)?;
                        chunks.push(ChunkArrayItem(hash, Some(buf.to_vec())));
                        chunk_start = pos;
                    }
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
        if chunks.len() > 0 {
            let mut indices = shuffle(&mut chunks);

            // Filter duplicates and construct the indice list.
            let mut uid_indices: HashMap<String, usize> = HashMap::new();
            chunks = chunks
                .into_iter()
                .enumerate()
                .filter(|(i, chunk)| {
                    let uid = &chunk.0;
                    match uid_indices.get(uid) {
                        Some(previous_index) => {
                            indices[*i] = *previous_index;
                            false
                        },
                        None => {
                            uid_indices.insert(uid.to_string(), *i);
                            true
                        }
                    }
                })
                .map(|(_, e)| e)
                .collect();

            // Encode the indice list in the first chunk:
            chunks[0].1 = match &chunks[0].1 {
                Some(buf) => Some(rmp_serde::to_vec_named(&(indices, buf))?),
                None => None,
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
        let encrypted_chunks: Result<Vec<_>> = chunks
            .into_iter()
            .map(encrypt_item)
            .collect();

        self.chunks = encrypted_chunks?;
        self.set_meta(crypto_manager, additional_data, &meta)?;

        Ok(())
    }

    pub fn decrypt_content(&self, crypto_manager: &ItemCryptoManager) -> Result<Vec<u8>> {
        let mut indices = None;
        let decrypt_item = |(i, item): (usize, &ChunkArrayItem)| -> Result<Vec<u8>> {
            let hash_str = &item.0;
            let buf = &item.1;
            let mut buf = match buf {
                Some(buf) => buffer_unpad(&crypto_manager.0.decrypt(&buf, None)?)?,
                None => return Err(Error::Generic("Got chunk without data".to_owned())),
            };

            // If we have the header, remove it before calculating the mac
            if i == 0 {
                let first_chunk: (Vec<usize>, Vec<u8>) = rmp_serde::from_read_ref(&buf)?;
                indices = Some(first_chunk.0);
                buf = first_chunk.1;
            }

            let hash = from_base64(&hash_str)?;
            let calculated_mac = crypto_manager.0.calculate_mac(&buf)?;

            if !memcmp(&hash, &calculated_mac) {
                return Err(Error::Integrity(format!("Got a wrong mac for chunk {}", hash_str)));
            }

            Ok(buf)
        };

        let decrypted_chunks: Result<Vec<_>> = self.chunks
            .iter()
            .enumerate()
            .map(decrypt_item)
            .collect();
        let decrypted_chunks = decrypted_chunks?;

        match indices {
            Some(indices) => {
                if indices.len() > 1 {
                    let sorted_chunks: Vec<u8> = indices
                        .into_iter()
                        .map(|index| &decrypted_chunks[index])
                        .flatten()
                        .map(|x| *x)
                        .collect::<Vec<u8>>();

                    Ok(sorted_chunks)
                } else {
                    Ok(decrypted_chunks.into_iter().nth(0).unwrap_or(vec![]))
                }
            },
            None => Ok(decrypted_chunks.into_iter().nth(0).unwrap_or(vec![]))
        }
    }

    pub fn delete(&mut self, crypto_manager: &ItemCryptoManager, additional_data: &[u8]) -> Result<()> {
        let meta = self.decrypt_meta(crypto_manager, additional_data)?;

        self.deleted = true;

        self.set_meta(crypto_manager, additional_data, &meta)?;
        Ok(())
    }
}

pub type Etag = Option<String>;

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
    pub fn new(parent_crypto_manager: &CollectionCryptoManager, meta: &ItemMetadata, content: &[u8]) -> Result<Self> {
        let meta = rmp_serde::to_vec_named(meta)?;
        Self::new_raw(parent_crypto_manager, &meta, content)
    }

    fn new_raw(parent_crypto_manager: &CollectionCryptoManager, meta: &[u8], content: &[u8]) -> Result<Self> {
        let uid = gen_uid_base64();
        let version = CURRENT_VERSION;
        let crypto_manager = Self::get_crypto_manager_static(parent_crypto_manager, &uid, version, None)?;
        let content = EncryptedRevision::new(&crypto_manager, Self::get_additional_mac_data_static(&uid), &meta, content)?;

        Ok(Self {
            uid,
            version,
            encryption_key: None,
            content,

            etag: RefCell::new(None),
        })
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
        self.content.verify(crypto_manager, self.get_additional_mac_data())
    }

    pub fn set_meta(&mut self, crypto_manager: &ItemCryptoManager, meta: &[u8]) -> Result<()> {
        let ad_mac_data = Self::get_additional_mac_data_static(&self.uid);
        if self.is_locally_changed() {
            self.content.set_meta(crypto_manager, ad_mac_data, meta)?;
        } else {
            let mut rev = self.content.clone();
            rev.set_meta(crypto_manager, ad_mac_data, meta)?;
            self.content = rev;
        };

        Ok(())
    }

    pub fn decrypt_meta(&self, crypto_manager: &ItemCryptoManager) -> Result<Vec<u8>> {
        self.verify(crypto_manager)?;
        self.content.decrypt_meta(crypto_manager, self.get_additional_mac_data())
    }

    pub fn set_content(&mut self, crypto_manager: &ItemCryptoManager, content: &[u8]) -> Result<()> {
        let ad_mac_data = Self::get_additional_mac_data_static(&self.uid);
        if self.is_locally_changed() {
            self.content.set_content(crypto_manager, ad_mac_data, content)?;
        } else {
            let mut rev = self.content.clone();
            rev.set_content(crypto_manager, ad_mac_data, content)?;
            self.content = rev;
        };

        Ok(())
    }

    pub fn decrypt_content(&self, crypto_manager: &ItemCryptoManager) -> Result<Vec<u8>> {
        self.verify(crypto_manager)?;
        self.content.decrypt_content(crypto_manager)
    }

    pub fn delete(&mut self, crypto_manager: &ItemCryptoManager) -> Result<()> {
        let ad_mac_data = Self::get_additional_mac_data_static(&self.uid);
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

    pub fn get_uid(&self) -> &str {
        &self.uid
    }

    pub fn get_etag(&self) -> Etag {
        self.etag.borrow().to_owned()
    }

    fn get_crypto_manager_static(parent_crypto_manager: &CollectionCryptoManager, uid: &str, version: u8, encryption_key: Option<&[u8]>) -> Result<ItemCryptoManager> {
        let encryption_key = match encryption_key {
            Some(encryption_key) => parent_crypto_manager.0.decrypt(encryption_key, None)?,
            None => parent_crypto_manager.0.derive_subkey(uid.as_bytes())?,
        };

        ItemCryptoManager::new(try_into!(&encryption_key[..])?, version)
    }

    pub fn get_crypto_manager(&self, parent_crypto_manager: &CollectionCryptoManager) -> Result<ItemCryptoManager> {
        let encryption_key = self.encryption_key.as_deref().and_then(|x| Some(&x[..]));
        Self::get_crypto_manager_static(parent_crypto_manager, &self.uid, self.version, encryption_key)
    }

    fn get_additional_mac_data_static(uid: &str) -> &[u8] {
        uid.as_bytes()
    }

    fn get_additional_mac_data(&self) -> &[u8] {
        Self::get_additional_mac_data_static(&self.uid)
    }

    pub(crate) fn test_get_chunk_uids(&self) -> Vec<String> {
        self.content.chunks
            .iter()
            .map(|x| x.0.clone())
            .collect()
    }
}
