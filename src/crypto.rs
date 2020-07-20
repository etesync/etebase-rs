// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::convert::TryInto;

use sodiumoxide::crypto::{
    aead::xchacha20poly1305_ietf as aead,
    box_,
    generichash,
    kdf,
    sign,
    scalarmult,
    pwhash::argon2id13,
};

use super::error::{
    Error,
    Result,
};

macro_rules! to_enc_error {
    ($x:expr, $msg:tt) => {
        ($x).or(Err(Error::Encryption($msg)))
    }
}

fn generichash_quick(msg: &[u8], key: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut state = to_enc_error!(generichash::State::new(32, key), "Failed to init hash")?;
    to_enc_error!(state.update(msg), "Failed to update hash")?;
    Ok(to_enc_error!(state.finalize(), "Failed to finalize hash")?.as_ref().to_vec())
}

pub fn init() -> Result<()> {
    to_enc_error!(sodiumoxide::init(), "Failed initialising libsodium")
}

pub fn derive_key(salt: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut key = vec![0; 32];
    let salt = &salt[..argon2id13::SALTBYTES];
    let salt: &[u8; argon2id13::SALTBYTES] = to_enc_error!(salt.try_into(), "Expect salt to be at least 16 bytes")?;
    let password = password.as_bytes();

    let ret = argon2id13::derive_key(&mut key, password, &argon2id13::Salt(*salt), argon2id13::OPSLIMIT_SENSITIVE, argon2id13::MEMLIMIT_MODERATE);
    Ok(to_enc_error!(ret, "pwhash failed")?.as_ref().to_vec())
}

pub struct CryptoManager {
    pub version: u8,
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
    asym_key_seed: [u8; 32],
    sub_derivation_key: [u8; 32],
}

impl CryptoManager {
    pub fn new(key: &[u8; 32], context: &[u8; 8], version: u8) -> Result<CryptoManager> {
        let key = kdf::Key(*key);
        let mut cipher_key = [0; 32];
        let mut mac_key = [0; 32];
        let mut asym_key_seed = [0; 32];
        let mut sub_derivation_key = [0; 32];

        to_enc_error!(kdf::derive_from_key(&mut cipher_key, 1, *context, &key), "Failed deriving key")?;
        to_enc_error!(kdf::derive_from_key(&mut mac_key, 2, *context, &key), "Failed deriving key")?;
        to_enc_error!(kdf::derive_from_key(&mut asym_key_seed, 3, *context, &key), "Failed deriving key")?;
        to_enc_error!(kdf::derive_from_key(&mut sub_derivation_key, 4, *context, &key), "Failed deriving key")?;

        Ok(CryptoManager {
            version,
            cipher_key,
            mac_key,
            asym_key_seed,
            sub_derivation_key,
        })
    }

    pub fn encrypt(&self, msg: &[u8], additional_data: Option<&[u8]>) -> Result<Vec<u8>> {
        let key = aead::Key(self.cipher_key);
        let nonce = aead::gen_nonce();
        let encrypted = aead::seal(msg, additional_data, &nonce, &key);
        let mut ret = vec![0; aead::NONCEBYTES + encrypted.len()];
        ret[..aead::NONCEBYTES].copy_from_slice(nonce.as_ref());
        ret[aead::NONCEBYTES..].copy_from_slice(&encrypted);

        Ok(ret)
    }

    pub fn decrypt(&self, cipher: &[u8], additional_data: Option<&[u8]>) -> Result<Vec<u8>> {
        let key = aead::Key(self.cipher_key);
        let nonce = &cipher[..aead::NONCEBYTES];
        let nonce: &[u8; aead::NONCEBYTES] = to_enc_error!(nonce.try_into(), "Got a nonce of a wrong size")?;
        let cipher = &cipher[aead::NONCEBYTES..];
        Ok(to_enc_error!(aead::open(cipher, additional_data, &aead::Nonce(*nonce), &key), "decryption failed")?)
    }

    pub fn encrypt_detached(&self, msg: &[u8], additional_data: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = aead::Key(self.cipher_key);
        let nonce = aead::gen_nonce();
        let mut encrypted = msg.clone().to_owned();
        let tag = aead::seal_detached(&mut encrypted[..], additional_data, &nonce, &key);
        let mut ret = vec![0; aead::NONCEBYTES + encrypted.len()];
        ret[..aead::NONCEBYTES].copy_from_slice(nonce.as_ref());
        ret[aead::NONCEBYTES..].copy_from_slice(&encrypted);

        Ok((tag[..].to_owned(), ret))
    }

    pub fn decrypt_detached(&self, cipher: &[u8], tag: &[u8; aead::TAGBYTES], additional_data: Option<&[u8]>) -> Result<Vec<u8>> {
        let key = aead::Key(self.cipher_key);
        let tag = aead::Tag(*tag);
        let nonce = &cipher[..aead::NONCEBYTES];
        let nonce: &[u8; aead::NONCEBYTES] = to_enc_error!(nonce.try_into(), "Got a nonce of a wrong size")?;
        let cipher = &cipher[aead::NONCEBYTES..];
        let mut decrypted = cipher.clone().to_owned();
        to_enc_error!(aead::open_detached(&mut decrypted[..], additional_data, &tag, &aead::Nonce(*nonce), &key), "decryption failed")?;

        Ok(decrypted)
    }

    pub fn verify(&self, cipher: &[u8], tag: &[u8; aead::TAGBYTES], additional_data: Option<&[u8]>) -> Result<bool> {
        let key = aead::Key(self.cipher_key);
        let tag = aead::Tag(*tag);
        let nonce = &cipher[..aead::NONCEBYTES];
        let nonce: &[u8; aead::NONCEBYTES] = to_enc_error!(nonce.try_into(), "Got a nonce of a wrong size")?;
        let cipher = &cipher[aead::NONCEBYTES..];
        let mut decrypted = cipher.clone().to_owned();
        to_enc_error!(aead::open_detached(&mut decrypted[..], additional_data, &tag, &aead::Nonce(*nonce), &key), "decryption failed")?;

        Ok(true)
    }

    pub fn derive_subkey(&self, salt: &[u8]) -> Result<Vec<u8>> {
        generichash_quick(&self.sub_derivation_key, Some(salt))
    }

    pub fn calculate_mac(&self, msg: &[u8]) -> Result<Vec<u8>> {
        generichash_quick(msg, Some(&self.mac_key))
    }

    pub fn calculate_hash(&self, msg: &[u8]) -> Result<Vec<u8>> {
        generichash_quick(msg, None)
    }
}

pub struct LoginCryptoManager {
    pubkey: sign::PublicKey,
    privkey: sign::SecretKey,
}

impl LoginCryptoManager {
    pub fn keygen(seed: &[u8; 32]) -> Result<LoginCryptoManager> {
        let seed = sign::Seed(*seed);
        let (pubkey, privkey) = sign::keypair_from_seed(&seed);

        Ok(LoginCryptoManager {
            privkey,
            pubkey,
        })
    }

    pub fn sign_detached(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let ret = sign::sign_detached(msg, &self.privkey);

        Ok(ret[..].to_vec())
    }

    pub fn verify_detached(&self, msg: &[u8], signature: &[u8], pubkey: &[u8; sign::PUBLICKEYBYTES]) -> Result<bool> {
        let mut signature_copy = [0; 64];
        signature_copy[..].copy_from_slice(&signature[..]);
        let signature = sign::Signature(signature_copy);
        let pubkey = sign::PublicKey(*pubkey);
        let ret = sign::verify_detached(&signature, msg, &pubkey);

        Ok(ret)
    }

    pub fn get_pubkey(&self) -> Vec<u8> {
        self.pubkey[..].to_vec()
    }
}

pub struct BoxCryptoManager {
    pubkey: box_::PublicKey,
    privkey: box_::SecretKey,
}

impl BoxCryptoManager {
    pub fn keygen(seed: Option<&[u8; 32]>) -> Result<BoxCryptoManager> {
        let (pubkey, privkey) = match seed {
            Some(seed) => {
                let seed = box_::Seed(*seed);
                box_::keypair_from_seed(&seed)
            }
            None => box_::gen_keypair(),
        };

        Ok(BoxCryptoManager {
            privkey,
            pubkey,
        })
    }

    pub fn from_privkey(privkey: &[u8; box_::SECRETKEYBYTES]) -> Result<BoxCryptoManager> {
        let privkey_scalar = scalarmult::Scalar(*privkey);
        let privkey = box_::SecretKey(*privkey);
        let pubkey_scalar = scalarmult::scalarmult_base(&privkey_scalar);
        let pubkey = box_::PublicKey(pubkey_scalar[..].try_into().unwrap());

        Ok(BoxCryptoManager {
            privkey,
            pubkey,
        })
    }

    pub fn encrypt(&self, msg: &[u8], pubkey: &[u8; box_::PUBLICKEYBYTES]) -> Result<Vec<u8>> {
        let pubkey = box_::PublicKey(pubkey[..].try_into().unwrap());
        let privkey = box_::SecretKey(self.privkey[..].try_into().unwrap());
        let nonce = box_::gen_nonce();
        let encrypted = box_::seal(msg, &nonce, &pubkey, &privkey);
        let mut ret = vec![0; box_::NONCEBYTES + encrypted.len()];
        ret[..box_::NONCEBYTES].copy_from_slice(nonce.as_ref());
        ret[box_::NONCEBYTES..].copy_from_slice(&encrypted);

        Ok(ret)
    }

    pub fn decrypt(&self, cipher: &[u8], pubkey: &[u8; sign::PUBLICKEYBYTES]) -> Result<Vec<u8>> {
        let pubkey = box_::PublicKey(pubkey[..].try_into().unwrap());
        let privkey = box_::SecretKey(self.privkey[..].try_into().unwrap());
        let nonce = &cipher[..box_::NONCEBYTES];
        let nonce: &[u8; box_::NONCEBYTES] = to_enc_error!(nonce.try_into(), "Got a nonce of a wrong size")?;
        let cipher = &cipher[box_::NONCEBYTES..];
        Ok(to_enc_error!(box_::open(cipher, &box_::Nonce(*nonce), &pubkey, &privkey), "decryption failed")?)
    }

    pub fn get_pubkey(&self) -> Vec<u8> {
        self.pubkey[..].to_vec()
    }

    pub fn get_privkey(&self) -> Vec<u8> {
        self.privkey[..].to_vec()
    }
}
