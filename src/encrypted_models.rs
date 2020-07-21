// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate rmp_serde;

use std::convert::TryInto;

use serde::{Serialize, Deserialize};

use super::{
    try_into,
    CURRENT_VERSION,
    crypto::{
        CryptoManager,
        CryptoMac,
    },
    error::{
        Error,
        Result,
    },
    utils::{
        buffer_pad_meta,
        buffer_pad,
        buffer_unpad,
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

pub type CollectionSerialWrite = EncryptedCollection;
pub type CollectionSerialRead = EncryptedCollection;

#[derive(Serialize, Deserialize, Clone)]
enum CollectionAccessLevel {
    #[serde(rename = "adm")]
    Admin,
    #[serde(rename = "rw")]
    ReadWrite,
    #[serde(rename = "ro")]
    ReadOnly,
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
    // FIXME: meta should be a special struct that we have that we let people manipulate
    pub fn new(parent_crypto_manager: &AccountCryptoManager, meta: &[u8], content: &[u8]) -> Result<Self> {
        let version = CURRENT_VERSION;
        let collection_key = parent_crypto_manager.0.encrypt(&randombytes(SYMMETRIC_KEY_SIZE), None)?;
        let crypto_manager = Self::get_crypto_manager_static(parent_crypto_manager, version, &collection_key)?;
        let item = EncryptedItem::new(&crypto_manager, meta, content)?;

        Ok(Self {
            item,
            access_level: CollectionAccessLevel::Admin,
            collection_key,

            stoken: None,
        })
    }

    pub fn deserialize(serialized: CollectionSerialRead) -> Self {
        serialized
    }

    pub fn serialize(&self) -> &CollectionSerialWrite {
        self
    }

    pub(crate) fn mark_saved(&mut self) {
        self.item.mark_saved();
    }

    pub fn verify(&self, crypto_manager: &CollectionCryptoManager) -> Result<bool> {
        let item_crypto_manager = self.item.get_crypto_manager(crypto_manager)?;
        self.item.verify(&item_crypto_manager)
    }

    // FIXME: meta should be a special struct that we have that we let people manipulate
    pub fn set_meta(&mut self, crypto_manager: &CollectionCryptoManager, meta: &[u8]) -> Result<()> {
        let item_crypto_manager = self.item.get_crypto_manager(crypto_manager)?;
        self.item.set_meta(&item_crypto_manager, meta)
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

    pub fn get_etag(&self) -> Option<&str> {
        self.item.get_etag()
    }

    pub fn get_stoken(&self) -> Option<&str> {
        self.stoken.as_deref()
    }

    fn get_crypto_manager_static(parent_crypto_manager: &AccountCryptoManager, version: u8, encryption_key: &[u8]) -> Result<CollectionCryptoManager> {
        let encryption_key = parent_crypto_manager.0.decrypt(encryption_key, None)?;

        CollectionCryptoManager::new(try_into!(&encryption_key[..])?, version)
    }

    pub fn get_crypto_manager(&self, parent_crypto_manager: &AccountCryptoManager) -> Result<CollectionCryptoManager> {
        Self::get_crypto_manager_static(parent_crypto_manager, self.item.version, &self.collection_key)
    }
}


type ChunkArrayItem = (StringBase64, Option<Vec<u8>>);

pub type RevisionSerialWrite = EncryptedRevision;
pub type RevisionSerialRead = EncryptedRevision;

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

    pub fn deserialize(serialized: RevisionSerialRead) -> Self {
        serialized
    }

    pub fn serialize(&self) -> &RevisionSerialWrite {
        self
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
        let chunk_start = 0;

        if content.len() > min_chunk {
            return Err(Error::Generic("FIXME: tbd".to_owned()));
        }

        if chunk_start < content.len() {
            let buf = &content[chunk_start..];
            let hash = to_base64(&crypto_manager.0.calculate_mac(buf)?)?;
            chunks.push((hash, Some(buf.to_vec())));
        }

        if chunks.len() > 1 {
            return Err(Error::Generic("FIXME: tbd 2".to_owned()));
        }

        let encrypt_item = |item: ChunkArrayItem| -> Result<ChunkArrayItem> {
            let (hash, buf) = item;
            let ret = match buf {
                Some(buf) => Some(crypto_manager.0.encrypt(&buffer_pad(&buf)?, None)?),
                None => None,
            };

            Ok((hash, ret))
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

    pub fn decrypt_content(&self, crypto_manager: &ItemCryptoManager, additional_data: &[u8]) -> Result<Vec<u8>> {
        let decrypt_item = |item: &ChunkArrayItem| -> Result<Vec<u8>> {
            let (hash_str, buf) = item;
            let buf = match buf {
                Some(buf) => buffer_unpad(&crypto_manager.0.decrypt(&buf, None)?)?,
                None => return Err(Error::Generic("Got chunk without data".to_owned())),
            };

            let hash = from_base64(&hash_str)?;
            let calculated_mac = crypto_manager.0.calculate_mac(&buf)?;

            if !memcmp(&hash, &calculated_mac) {
                return Err(Error::Integrity(format!("Got a wrong mac for chunk {}", hash_str)));
            }

            Ok(buf)
        };

        let decrypted_chunks: Result<Vec<_>> = self.chunks
            .iter()
            .map(decrypt_item)
            .collect();
        let decrypted_chunks = decrypted_chunks?;

        let ret = if decrypted_chunks.len() > 1 {
            Err(Error::Generic("FIXME: tbd 3".to_owned()))
        } else {
            Ok(decrypted_chunks.into_iter().nth(0).unwrap_or(vec![]))
        };

        ret
    }

    pub fn delete(&mut self, crypto_manager: &ItemCryptoManager, additional_data: &[u8]) -> Result<()> {
        let meta = self.decrypt_meta(crypto_manager, additional_data)?;

        self.deleted = true;

        self.set_meta(crypto_manager, additional_data, &meta)?;
        Ok(())
    }
}

pub type ItemSerialWrite = EncryptedItem;
pub type ItemSerialRead = EncryptedItem;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedItem {
    uid: StringBase64,
    version: u8,

    #[serde(with = "serde_bytes")]
    encryption_key: Option<Vec<u8>>,
    content: EncryptedRevision,

    etag: Option<String>,
}

impl EncryptedItem {
    // FIXME: meta should be a special struct that we have that we let people manipulate
    pub fn new(parent_crypto_manager: &CollectionCryptoManager, meta: &[u8], content: &[u8]) -> Result<Self> {
        let uid = gen_uid_base64();
        let version = CURRENT_VERSION;
        let crypto_manager = Self::get_crypto_manager_static(parent_crypto_manager, &uid, version, None)?;
        let content = EncryptedRevision::new(&crypto_manager, Self::get_additional_mac_data_static(&uid), meta, content)?;

        Ok(Self {
            uid,
            version,
            encryption_key: None,
            content,

            etag: None,
        })
    }

    pub fn deserialize(serialized: ItemSerialRead) -> Self {
        serialized
    }

    pub fn serialize(&self) -> &ItemSerialWrite {
        self
    }

    pub(crate) fn mark_saved(&mut self) {
        self.etag = Some(self.content.uid.clone());
    }

    pub fn is_locally_changed(&self) -> bool {
        match self.etag.as_deref() {
            Some(etag) => etag == self.content.uid,
            None => false,
        }
    }

    pub fn verify(&self, crypto_manager: &ItemCryptoManager) -> Result<bool> {
        self.content.verify(crypto_manager, self.get_additional_mac_data())
    }

    // FIXME: meta should be a special struct that we have that we let people manipulate
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
        self.content.decrypt_content(crypto_manager, self.get_additional_mac_data())
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

    pub fn get_etag(&self) -> Option<&str> {
        self.etag.as_deref()
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
}
