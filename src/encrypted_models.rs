// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate rmp_serde;

use std::convert::TryInto;

use serde::{Serialize, Deserialize};

use super::{
    try_into,
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
    },
};

pub fn gen_uid_base64() -> StringBase64 {
  return to_base64(&randombytes(24)).unwrap();
}

pub type CollectionSerialWrite = EncryptedCollection;
pub type CollectionSerialRead = EncryptedCollection;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedCollection {
    access_level: String,
    #[serde(with = "serde_bytes")]
    collection_key: Vec<u8>,
    stoken: Option<String>,
}

impl EncryptedCollection {
    pub fn deserialize(serialized: CollectionSerialRead) -> Self {
        serialized
    }

    pub fn serialize(&self) -> &CollectionSerialWrite {
        self
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
    pub fn new(crypto_manager: &CryptoManager, additional_data: &[u8], meta: &[u8], content: &[u8]) -> Result<Self> {
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

    fn calculate_hash(&self, crypto_manager: &CryptoManager, additional_data: &[u8]) -> Result<Vec<u8>> {
        let mut crypto_mac = crypto_manager.get_crypto_mac()?;
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

    pub fn verify(&self, crypto_manager: &CryptoManager, additional_data: &[u8]) -> Result<bool> {
        let mac = from_base64(&self.uid)?;
        let ad_hash = self.calculate_hash(crypto_manager, additional_data)?;

        crypto_manager.verify(&self.meta, try_into!(&mac[..])?, Some(&ad_hash))
    }

    pub fn set_meta(&mut self, crypto_manager: &CryptoManager, additional_data: &[u8], meta: &[u8]) -> Result<()> {
        let ad_hash = self.calculate_hash(crypto_manager, additional_data)?;

        let msg = buffer_pad_meta(meta)?;
        let enc_content = crypto_manager.encrypt_detached(&msg, Some(&ad_hash))?;

        self.uid = to_base64(&enc_content.0)?;
        self.meta = enc_content.1;

        Ok(())
    }

    pub fn decrypt_meta(&self, crypto_manager: &CryptoManager, additional_data: &[u8]) -> Result<Vec<u8>> {
        let mac = from_base64(&self.uid)?;
        let ad_hash = self.calculate_hash(crypto_manager, additional_data)?;

        buffer_unpad(&crypto_manager.decrypt_detached(&self.meta, try_into!(&mac[..])?, Some(&ad_hash))?)
    }

    pub fn set_content(&mut self, crypto_manager: &CryptoManager, additional_data: &[u8], content: &[u8]) -> Result<()> {
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
            let hash = to_base64(&crypto_manager.calculate_mac(buf)?)?;
            chunks.push((hash, Some(buf.to_vec())));
        }

        if chunks.len() > 1 {
            return Err(Error::Generic("FIXME: tbd 2".to_owned()));
        }

        let encrypt_item = |item: ChunkArrayItem| -> Result<ChunkArrayItem> {
            let (hash, buf) = item;
            let ret = match buf {
                Some(buf) => Some(crypto_manager.encrypt(&buffer_pad(&buf)?, None)?),
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

    pub fn decrypt_content(&self, crypto_manager: &CryptoManager, additional_data: &[u8]) -> Result<Vec<u8>> {
        let decrypt_item = |item: &ChunkArrayItem| -> Result<Vec<u8>> {
            let (hash_str, buf) = item;
            let buf = match buf {
                Some(buf) => buffer_unpad(&crypto_manager.decrypt(&buf, None)?)?,
                None => return Err(Error::Generic("Got chunk without data".to_owned())),
            };

            let hash = from_base64(&hash_str)?;
            let calculated_mac = crypto_manager.calculate_mac(&buf)?;

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

    pub fn delete(&mut self, crypto_manager: &CryptoManager, additional_data: &[u8]) -> Result<()> {
        let meta = self.decrypt_meta(crypto_manager, additional_data)?;

        self.deleted = true;

        self.set_meta(crypto_manager, additional_data, &meta)?;
        Ok(())
    }
}
