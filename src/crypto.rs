// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::convert::TryInto;

use sodiumoxide::crypto::{
    aead::xchacha20poly1305_ietf as aead, box_, generichash, kdf, pwhash::argon2id13, scalarmult,
    sign,
};

use crate::utils::{SALT_LENGTH, SYMMETRIC_KEY_SIZE};

use super::error::{Error, Result};

macro_rules! to_enc_error {
    ($x:expr, $msg:tt) => {
        ($x).or(Err(Error::Encryption($msg)))
    };
}

fn generichash_quick(msg: &[u8], key: Option<&[u8]>) -> Result<[u8; 32]> {
    let mut state = to_enc_error!(
        generichash::State::new(Some(32), key),
        "Failed to init hash"
    )?;
    to_enc_error!(state.update(msg), "Failed to update hash")?;
    Ok(to_enc_error!(state.finalize(), "Failed to finalize hash")?
        .as_ref()
        .try_into()
        .expect("generichash returned result of wrong size"))
}

pub fn init() -> Result<()> {
    to_enc_error!(sodiumoxide::init(), "Failed initialising libsodium")
}

pub fn derive_key(salt: &[u8; SALT_LENGTH], password: &str) -> Result<[u8; SYMMETRIC_KEY_SIZE]> {
    let mut key = [0; SYMMETRIC_KEY_SIZE];
    let password = password.as_bytes();

    argon2id13::derive_key(
        &mut key,
        password,
        &argon2id13::Salt(*salt),
        argon2id13::OPSLIMIT_SENSITIVE,
        argon2id13::MEMLIMIT_MODERATE,
    )
    .map_err(|_| Error::Encryption("pwhash failed"))?;

    Ok(key)
}

pub struct CryptoManager {
    pub version: u8,
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
    pub asym_key_seed: [u8; 32],
    sub_derivation_key: [u8; 32],
    deterministic_encryption_key: [u8; 32],
}

impl CryptoManager {
    pub fn new(key: &[u8; 32], context: &[u8; 8], version: u8) -> Result<Self> {
        let key = kdf::Key(*key);
        let mut cipher_key = [0; 32];
        let mut mac_key = [0; 32];
        let mut asym_key_seed = [0; 32];
        let mut sub_derivation_key = [0; 32];
        let mut deterministic_encryption_key = [0; 32];

        to_enc_error!(
            kdf::derive_from_key(&mut cipher_key, 1, *context, &key),
            "Failed deriving key"
        )?;
        to_enc_error!(
            kdf::derive_from_key(&mut mac_key, 2, *context, &key),
            "Failed deriving key"
        )?;
        to_enc_error!(
            kdf::derive_from_key(&mut asym_key_seed, 3, *context, &key),
            "Failed deriving key"
        )?;
        to_enc_error!(
            kdf::derive_from_key(&mut sub_derivation_key, 4, *context, &key),
            "Failed deriving key"
        )?;
        to_enc_error!(
            kdf::derive_from_key(&mut deterministic_encryption_key, 5, *context, &key),
            "Failed deriving key"
        )?;

        Ok(Self {
            version,
            cipher_key,
            mac_key,
            asym_key_seed,
            sub_derivation_key,
            deterministic_encryption_key,
        })
    }

    pub fn encrypt(&self, msg: &[u8], additional_data: Option<&[u8]>) -> Result<Vec<u8>> {
        let key = aead::Key(self.cipher_key);
        let nonce = aead::gen_nonce();
        let encrypted = aead::seal(msg, additional_data, &nonce, &key);
        let ret = [nonce.as_ref(), &encrypted].concat();

        Ok(ret)
    }

    pub fn decrypt(&self, cipher: &[u8], additional_data: Option<&[u8]>) -> Result<Vec<u8>> {
        let key = aead::Key(self.cipher_key);
        let nonce = &cipher[..aead::NONCEBYTES];
        let nonce: &[u8; aead::NONCEBYTES] =
            to_enc_error!(nonce.try_into(), "Got a nonce of a wrong size")?;
        let cipher = &cipher[aead::NONCEBYTES..];
        Ok(to_enc_error!(
            aead::open(cipher, additional_data, &aead::Nonce(*nonce), &key),
            "decryption failed"
        )?)
    }

    pub fn encrypt_detached(
        &self,
        msg: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = aead::Key(self.cipher_key);
        let nonce = aead::gen_nonce();
        let mut encrypted = msg.to_owned();
        let tag = aead::seal_detached(&mut encrypted[..], additional_data, &nonce, &key);
        let ret = [nonce.as_ref(), &encrypted].concat();

        Ok((tag[..].to_owned(), ret))
    }

    pub fn decrypt_detached(
        &self,
        cipher: &[u8],
        tag: &[u8; aead::TAGBYTES],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let key = aead::Key(self.cipher_key);
        let tag = aead::Tag(*tag);
        let nonce = &cipher[..aead::NONCEBYTES];
        let nonce: &[u8; aead::NONCEBYTES] =
            to_enc_error!(nonce.try_into(), "Got a nonce of a wrong size")?;
        let cipher = &cipher[aead::NONCEBYTES..];
        let mut decrypted = cipher.to_owned();
        to_enc_error!(
            aead::open_detached(
                &mut decrypted[..],
                additional_data,
                &tag,
                &aead::Nonce(*nonce),
                &key
            ),
            "decryption failed"
        )?;

        Ok(decrypted)
    }

    pub fn verify(
        &self,
        cipher: &[u8],
        tag: &[u8; aead::TAGBYTES],
        additional_data: Option<&[u8]>,
    ) -> Result<bool> {
        let key = aead::Key(self.cipher_key);
        let tag = aead::Tag(*tag);
        let nonce = &cipher[..aead::NONCEBYTES];
        let nonce: &[u8; aead::NONCEBYTES] =
            to_enc_error!(nonce.try_into(), "Got a nonce of a wrong size")?;
        let cipher = &cipher[aead::NONCEBYTES..];
        let mut decrypted = cipher.to_owned();
        to_enc_error!(
            aead::open_detached(
                &mut decrypted[..],
                additional_data,
                &tag,
                &aead::Nonce(*nonce),
                &key
            ),
            "decryption failed"
        )?;

        Ok(true)
    }

    pub fn deterministic_encrypt(
        &self,
        msg: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let key = aead::Key(self.deterministic_encryption_key);
        let mac = self.calculate_mac(msg)?;
        let nonce = &mac[..aead::NONCEBYTES];
        let nonce: &[u8; aead::NONCEBYTES] =
            to_enc_error!(nonce.try_into(), "Got a nonce of a wrong size")?;
        let encrypted = aead::seal(msg, additional_data, &aead::Nonce(*nonce), &key);
        let ret = [nonce.as_ref(), &encrypted].concat();

        Ok(ret)
    }

    pub fn deterministic_decrypt(
        &self,
        cipher: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let key = aead::Key(self.deterministic_encryption_key);
        let nonce = &cipher[..aead::NONCEBYTES];
        let nonce: &[u8; aead::NONCEBYTES] =
            to_enc_error!(nonce.try_into(), "Got a nonce of a wrong size")?;
        let cipher = &cipher[aead::NONCEBYTES..];
        Ok(to_enc_error!(
            aead::open(cipher, additional_data, &aead::Nonce(*nonce), &key),
            "decryption failed"
        )?)
    }

    pub fn derive_subkey(&self, salt: &[u8]) -> Result<[u8; 32]> {
        generichash_quick(&self.sub_derivation_key, Some(salt))
    }

    pub fn crypto_mac(&self) -> Result<CryptoMac> {
        CryptoMac::new(Some(&self.mac_key))
    }

    pub fn calculate_mac(&self, msg: &[u8]) -> Result<[u8; 32]> {
        generichash_quick(msg, Some(&self.mac_key))
    }

    pub fn calculate_hash(&self, msg: &[u8]) -> Result<[u8; 32]> {
        generichash_quick(msg, None)
    }
}

pub struct LoginCryptoManager {
    pubkey: sign::PublicKey,
    privkey: sign::SecretKey,
}

impl LoginCryptoManager {
    pub fn keygen(seed: &[u8; 32]) -> Result<Self> {
        let seed = sign::Seed(*seed);
        let (pubkey, privkey) = sign::keypair_from_seed(&seed);

        Ok(Self { privkey, pubkey })
    }

    pub fn sign_detached(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let ret = sign::sign_detached(msg, &self.privkey);

        Ok(ret.to_bytes().to_vec())
    }

    pub fn verify_detached(
        &self,
        msg: &[u8],
        signature: &[u8],
        pubkey: &[u8; sign::PUBLICKEYBYTES],
    ) -> Result<bool> {
        let mut signature_copy = [0; 64];
        signature_copy[..].copy_from_slice(signature);
        let signature = to_enc_error!(
            sign::Signature::from_bytes(&signature_copy),
            "siganture copy failed"
        )?;
        let pubkey = sign::PublicKey(*pubkey);
        let ret = sign::verify_detached(&signature, msg, &pubkey);

        Ok(ret)
    }

    pub fn pubkey(&self) -> &[u8] {
        &self.pubkey[..]
    }
}

pub struct BoxCryptoManager {
    pubkey: box_::PublicKey,
    privkey: box_::SecretKey,
}

impl BoxCryptoManager {
    pub fn keygen(seed: Option<&[u8; 32]>) -> Result<Self> {
        let (pubkey, privkey) = match seed {
            Some(seed) => {
                let seed = box_::Seed(*seed);
                box_::keypair_from_seed(&seed)
            }
            None => box_::gen_keypair(),
        };

        Ok(Self { privkey, pubkey })
    }

    pub fn from_privkey(privkey: &[u8; box_::SECRETKEYBYTES]) -> Result<BoxCryptoManager> {
        let privkey_scalar = scalarmult::Scalar(*privkey);
        let privkey = box_::SecretKey(*privkey);
        let pubkey_scalar = scalarmult::scalarmult_base(&privkey_scalar);
        let pubkey = box_::PublicKey(pubkey_scalar.0);

        Ok(BoxCryptoManager { privkey, pubkey })
    }

    pub fn encrypt(&self, msg: &[u8], pubkey: &[u8; box_::PUBLICKEYBYTES]) -> Result<Vec<u8>> {
        let pubkey = box_::PublicKey(*pubkey);
        let privkey = box_::SecretKey(self.privkey.0);
        let nonce = box_::gen_nonce();
        let encrypted = box_::seal(msg, &nonce, &pubkey, &privkey);
        let ret = [nonce.as_ref(), &encrypted].concat();

        Ok(ret)
    }

    pub fn decrypt(&self, cipher: &[u8], pubkey: &[u8; sign::PUBLICKEYBYTES]) -> Result<Vec<u8>> {
        let pubkey = box_::PublicKey(*pubkey);
        let privkey = box_::SecretKey(self.privkey.0);
        let nonce = &cipher[..box_::NONCEBYTES];
        let nonce: &[u8; box_::NONCEBYTES] =
            to_enc_error!(nonce.try_into(), "Got a nonce of a wrong size")?;
        let cipher = &cipher[box_::NONCEBYTES..];
        Ok(to_enc_error!(
            box_::open(cipher, &box_::Nonce(*nonce), &pubkey, &privkey),
            "decryption failed"
        )?)
    }

    pub fn pubkey(&self) -> &[u8] {
        &self.pubkey[..]
    }

    pub fn privkey(&self) -> &[u8] {
        &self.privkey[..]
    }
}

pub struct CryptoMac {
    state: generichash::State,
}

impl CryptoMac {
    pub fn new(key: Option<&[u8]>) -> Result<Self> {
        let state = to_enc_error!(
            generichash::State::new(Some(32), key),
            "Failed to init hash"
        )?;

        Ok(Self { state })
    }

    pub fn update(&mut self, msg: &[u8]) -> Result<()> {
        Ok(to_enc_error!(
            self.state.update(msg),
            "Failed to update hash"
        )?)
    }

    pub fn update_with_len_prefix(&mut self, msg: &[u8]) -> Result<()> {
        let len = msg.len() as u32;
        to_enc_error!(
            self.state.update(&len.to_le_bytes()),
            "Failed to update hash"
        )?;
        to_enc_error!(self.state.update(msg), "Failed to update hash")?;

        Ok(())
    }

    pub fn finalize(self) -> Result<Vec<u8>> {
        Ok(
            to_enc_error!(self.state.finalize(), "Failed to finalize hash")?
                .as_ref()
                .to_vec(),
        )
    }
}

fn get_encoded_chunk(content: &[u8], suffix: &str) -> String {
    let num =
        (((content[0] as u32) << 16) + ((content[1] as u32) << 8) + (content[2] as u32)) % 100000;
    return format!("{:0>5}{}", num, suffix);
}

/// Return a pretty formatted fingerprint of the content
///
/// For example:
/// ```shell
/// 45680   71497   88570   93128
/// 19189   84243   25687   20837
/// 47924   46071   54113   18789
/// ```
///
/// # Arguments:
/// * `content` - the content to create a fingerprint for
pub fn pretty_fingerprint(content: &[u8]) -> String {
    let delimiter = "   ";
    let fingerprint = generichash_quick(content, None).unwrap();

    /* We use 3 bytes each time to generate a 5 digit number - this means 10 pairs for bytes 0-29
     * We then use bytes 29-31 for another number, and then the 3 most significant bits of each first byte for the last.
     */
    let mut last_num: u32 = 0;
    let parts = (0..10).into_iter().map(|i| {
        let suffix = if i % 4 == 3 { "\n" } else { delimiter };

        last_num = (last_num << 3) | ((fingerprint[i] as u32) & 0xE0) >> 5;
        get_encoded_chunk(&fingerprint[i * 3..], suffix)
    });

    let last_num = (0..10).into_iter().fold(0, |accum, i| {
        (accum << 3) | ((fingerprint[i] as u32) & 0xE0) >> 5
    }) % 100000;
    let last_num = format!("{:0>5}", last_num);
    let parts = parts
        .chain(std::iter::once(get_encoded_chunk(
            &fingerprint[29..],
            delimiter,
        )))
        .chain(std::iter::once(last_num));
    parts.collect::<String>()
}
