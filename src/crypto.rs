// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::convert::TryInto;

use sodiumoxide::crypto::{
    aead::xchacha20poly1305_ietf as aead, box_, generichash, kdf, pwhash::argon2id13, scalarmult,
    sign,
};

use crate::utils::{SALT_SIZE, SYMMETRIC_KEY_SIZE};

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

pub fn derive_key(salt: &[u8; SALT_SIZE], password: &str) -> Result<[u8; SYMMETRIC_KEY_SIZE]> {
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

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use crate::error::Result;
    use crate::utils::from_base64;

    const PASSWORD: &str = "SomePassword";
    const PUBKEY: &str = "CXNdzeU6FgHz9ei64wJbKDhHc0fkoJ1p_c8zGuFeuGA";

    const KEY: &str = "Eq9b_rdbzeiU3P4sg5qN24KXbNgy8GgCeC74nFF99hI";
    const SALT: &str = "6y7jUaojtLq6FISBWPjwXTeiYk5cTiz1oe6HVNGvn2E";

    #[test]
    fn derive_key() {
        crate::init().unwrap();

        let derived = super::derive_key(
            from_base64(SALT).unwrap()[..16].try_into().unwrap(),
            PASSWORD,
        )
        .unwrap();
        let expected = from_base64(KEY).unwrap();
        assert_eq!(&derived[..], &expected[..]);
    }

    #[test]
    fn crypto_manager() {
        crate::init().unwrap();

        let key = from_base64(KEY).unwrap();
        let context = b"Col     ";
        let crypto_manager = super::CryptoManager::new(
            &key[0..32].try_into().unwrap(),
            context,
            crate::CURRENT_VERSION,
        )
        .unwrap();
        let subkey = crypto_manager.derive_subkey(&[0; 32]).unwrap();

        assert_eq!(
            &subkey[..],
            from_base64("4w-VCSTETv26JjVlVlD2VaACcb6aQSD2JbF-e89xnaA").unwrap()
        );

        let hash = crypto_manager.calculate_mac(&[0; 32]).unwrap();
        assert_eq!(
            &hash[..],
            from_base64("bz6eMZdAkIuiLUuFDiVwuH3IFs4hYkRfhzang_JzHr8").unwrap()
        );

        let clear_text = b"This Is Some Test Cleartext.";
        let cipher = crypto_manager.encrypt(clear_text, None).unwrap();
        let decrypted = crypto_manager.decrypt(&cipher, None).unwrap();
        assert_eq!(clear_text, &decrypted[..]);

        let clear_text = b"This Is Some Test Cleartext.";
        let (tag, cipher) = crypto_manager.encrypt_detached(clear_text, None).unwrap();
        let tag: &[u8; 16] = &tag[..].try_into().unwrap();
        let decrypted = crypto_manager.decrypt_detached(&cipher, tag, None).unwrap();
        assert_eq!(clear_text, &decrypted[..]);

        crypto_manager.verify(&cipher, tag, None).unwrap();

        let mut crypto_mac = crypto_manager.crypto_mac().unwrap();
        crypto_mac.update(&[0; 4]).unwrap();
        assert_eq!(
            crypto_mac.finalize().unwrap(),
            from_base64("y5nYZ75gDUna4bnaAHobXUlgQoTKOnueNW_KCYxcAg4").unwrap()
        );
    }

    #[test]
    fn login_crypto_manager() {
        crate::init().unwrap();

        let login_crypto_manager = super::LoginCryptoManager::keygen(&[0; 32]).unwrap();

        let msg = b"This Is Some Test Cleartext.";
        let signature = login_crypto_manager.sign_detached(msg).unwrap();
        let pubkey = login_crypto_manager.pubkey();
        assert!(login_crypto_manager
            .verify_detached(msg, &signature, pubkey.try_into().unwrap())
            .unwrap());
    }

    #[test]
    fn box_crypto_manager() {
        crate::init().unwrap();

        let box_crypto_manager = super::BoxCryptoManager::keygen(None).unwrap();
        let box_crypto_manager2 = super::BoxCryptoManager::keygen(None).unwrap();

        let msg = b"This Is Some Test Cleartext.";
        let cipher = box_crypto_manager
            .encrypt(msg, box_crypto_manager2.pubkey().try_into().unwrap())
            .unwrap();
        let decrypted = box_crypto_manager2
            .decrypt(&cipher[..], box_crypto_manager.pubkey().try_into().unwrap())
            .unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn crypto_mac() {
        crate::init().unwrap();

        let key = from_base64(KEY).unwrap();

        let mut crypto_mac = super::CryptoMac::new(None).unwrap();
        crypto_mac.update(&[0; 4]).unwrap();
        crypto_mac.update_with_len_prefix(&[0; 8]).unwrap();
        assert_eq!(
            crypto_mac.finalize().unwrap(),
            from_base64("P-Hpzo86RG6Ps4R1gGXmQrzmdJC2OotqqreKmB8G45A").unwrap()
        );

        let mut crypto_mac = super::CryptoMac::new(Some(&key)).unwrap();
        crypto_mac.update(&[0; 4]).unwrap();
        crypto_mac.update_with_len_prefix(&[0; 8]).unwrap();
        assert_eq!(
            crypto_mac.finalize().unwrap(),
            from_base64("rgL6d_XDiBfbzevFdtktc61XB5-PkS1uQ1cj5DgfFc8").unwrap()
        );
    }

    #[test]
    fn pretty_fingerprint() {
        crate::init().unwrap();

        let pubkey = from_base64(PUBKEY).unwrap();

        let fingerprint = super::pretty_fingerprint(&pubkey);
        assert_eq!(fingerprint, "45680   71497   88570   93128\n19189   84243   25687   20837\n47924   46071   54113   18789");
    }

    #[test]
    fn deterministic_encrypt() -> Result<()> {
        crate::init().unwrap();

        let key = from_base64(KEY)?;

        let context = b"Col     ";
        let crypto_manager = super::CryptoManager::new(
            &key[0..32].try_into().unwrap(),
            context,
            crate::CURRENT_VERSION,
        )
        .unwrap();

        // Deterministic encryption
        let clear_text = b"This Is Some Test Cleartext.";
        let cipher = crypto_manager
            .deterministic_encrypt(clear_text, None)
            .unwrap();
        let decrypted = crypto_manager.deterministic_decrypt(&cipher, None).unwrap();
        assert_eq!(clear_text, &decrypted[..]);

        let cipher2 = crypto_manager
            .deterministic_encrypt(clear_text, None)
            .unwrap();
        assert_eq!(cipher, cipher2);

        const BLOCK_SIZE: usize = 32;
        const PRECALC: [&str; BLOCK_SIZE * 2] = [
            "Jp5B3loU3qoohgvlOuiYcbEI1JUhHzwfKsqRRvR_KZFQWvJFn07eHg",
            "yeX7EzjL43RCN89Ch5RBjWkmIj4GwFNgKJhKYEmbn0Crgey8ScixVzk",
            "wq1YkcgH4XEkjRPb8A93Si6hVUdzekkx3Zi_RghmbPrnvdKHFAEp1oNk",
            "kctDIpfaUOgcUl-2Xtr64DO7zq4UX_z0HdrwcfZBAErcONQkdUv2N0Y3zA",
            "fkbl5El2TqjHPnQxg2u4IGtvqTbOEL9OwpZY8e0F6FyZDcBm24L5suM85jI",
            "snmNhMLHUM8dkeIJPD5Yj9v4IC32fIz-qQ1B59pHHBPmY4bxN-G0EjEgPiBM",
            "K1yLz2KUtZxFEe9bMgbJrzLW5zblZGRu2bYPlkGftwXNExEhgA60Pyz8wop9Ag",
            "Ieyj3IiI3GQ8PMY8QbCUzt4ni-jOTEa1igG6_k70gSE16Nhj8u3PN2uUhoP4hfw",
            "vGRqKW8it-OoQYl5sAsQiuQI4oocINk85bkq9v74st7nuYV8Hfqu_thhdpYztlGW",
            "Nsi1q71WXgQ1m1Qw7qZAjVv3TKvZwV64tAMyIPIfuIvQde4v0TzGCjkVdykssYFRGA",
            "R_pAHkt07ZR7kjAdE9rER9bxHTwyJjIDt3z61vhsh3mkOE9fxHaq_9rIFDzhc8RwzpA",
            "Xo_CNDIxokmU5Qwx8A3_WVbnvuQylNFM-NKwAj6bHHETi7iJQAuhK0GuY3COTbIf7q7b",
            "idxPqtKGk4dIiScBs98T-y96UE10hH-6xIdc25WN-VvhPo1x9Kfe8fmPBGUGeUO1wovaYg",
            "JYNRpo0r1xVrXdD27sHblDwT1p75TmHGDZpFoXvQtoC21xOup42g7cIJcxJH3Ew_enhu1w4",
            "L5LEscfqPzWWpZ5A1ok-ymlSwlyleuF-KupfJMkF0QHvYi-0pk5416nni6Yv4NJgB4Qe4_5D",
            "EVy8E401Licx7Pjg_3YdC0Ei9xqtAqzFApm_gzA47-1SAZr7aJbwSuWQTVcTX-7pNquBLqtZ8A",
            "KQN3_3r8n7HvrNu7XGXAvpyQayrc9xErVP1fOzfCXUaUmrHNiiEwPfKk5s5O0OkiPHhbbdKBV0k",
            "AH3PrPmGu1bIK782H4HXq-OwY-lIa8vHdSVL1FyrbfLHvycEQftHMZU6_GHZhMNsRQs4XpkmljHZ",
            "dqVa0LN4ZADsz9Fzk5Jmve8aUJ4yxeiCmbSjEo-uhfsjBawSYlpNnpMe6VTJvcuja0eKPkvFimPJpg",
            "f7UIdICsvS4DUSFPGPkmtpqJiqFuzHx0qi4vxTtNrBu1V7hbT2NZceYo4FJY4eT37E2Im1juv2CdrV8",
            "6zpSAooPLr3VP4Vo5TuTu-H5-sucMe6H4GbkY8Np_Z5HBQEpvRXaPzLlEyTV8bTILZLdYX6lHDdW_cxp",
            "B34WgoV9X5WUFbxz7u1LsnSyjU9CNQZ5E-P-BaZjAN_AtM7InIUDcsqQciWdWx2H3TFU6B79wkOcxHyWbA",
            "2peH_bAKZ8wpI_vZjfoTcFUenAxjQCUfqVMY0THEF92KFiwJzp8g-wNssn2M0NBCAEZ_9aYWF5wcNFWOjOw",
            "5069CemejoWosspugqz4hN8nBEYlChw714tnt2wp8071jJ9S46I5cNilKHJRMLj2-aGZcizcQi4ihgjLP6QN",
            "ymfpIBHspNuU4DKyceUEtAiztOgBpmZyp70jjNcVylrRzDHBZC_gfX7lKRwrz9DieyosS7cU1EIe30-zGjtQXA",
            "w1MKV555BID3wRfHjj-X91UJ9-UaTvflOmH1fI9j5yeYkMr9I2comXG8utjZhsIctZnD6RNfNa7fqQ2OdnS7WJM",
            "s4c8WeKXZLQtovpTZhKAGgPl9Akt9MFyUvV5L-boDD53RJ2K8AJ6SlrVJ5UXJa-vueiLYr2LBrdDCIo1aAenEpay",
            "-f8e84MQWdS-494BTj2uTn8wDS00YIQCv53YCSEMPXRQvJus8We-dBfrY9MGKAYj5qzvWD2AhpNPamzDEBu2XqZoMg",
            "c-XbLLQqWN9gTx_B-gXof4fqyMi26jvXI2_v3RRuMK1Hraz1TYj3WnE5LRENqkv74sokPCAgjrK38p269gCGxuKzofM",
            "bTLj08EChb3UH2XBfwXbiYbHAQfnf2480Lj5GvAr2r9UZ5HxdcUS0e19Xkp0kHRYHoNiW7Lf10qTUq6UhfLG1RHfm910",
            "odlwQWwzuIVkrTsItYppK4VCRilMmwjURouls_qsfwOnEWnL6mkaLIkrC6xzI34oFztuNxYniyyb9QPJ9mAyIGwEHCGKIA",
            "XfRyxsqIpNpVYTKLQqttbool_y55nTCLU0FtpYwKHrM8qxa-cOA8GzL8jds2E7PiLjXl5Q1L_id6ycQzfdBQ7WafB4hnqqw",
            "XTZco0R8H3bHobcXJ9c0-8KTRz-sqJQTtqiTk42mLzk4IhJyxv0aqpLX2kKnC3TXCLKWFEYZ1GZfczjeRtUCTYvxxFxzJVSD",
            "thoiDEkUe_QB2Nr9r8V-6xOwvUMHX26CvfRR1OLSItT9CtkygyJbDdHiVFtXdE6illf1-LVpvMLWIxCdvCJHDNfI2-AeBmE4Qg",
            "lsRvZEJM8jg02hi-iZjU4oUaG3ShY97bybmSyupYRmdWR_Mq6yx-mMdHuJ0FLJJwSLOdC8HJl7w2SHGSjISFdq_wyZUpT96BKyg",
            "MUUww8zlee8WL7VXf9db2_yY2Pq4qP4upLO9rYkwqON6LoXG3MVOWvm-CA_jOhkaKbait2di6thqPzcKjcnTg6S8dqBcVaEOSRXG",
            "fL9P3em0q_YKn92Shu1kT0icbPLcTdNrrDcGvsSTpm1bphqGchBGp1zFhS298x0IjMgqRh9oR9iPvGP4VmVZJfPwWtRZKxPoOalbDA",
            "jWi6aNkZ3AKfXmziTtB2RlKQS9gn3FrEsObeBkkKpYg0NQZ3v1r4ctlCjNf9U-SDS7XqOoRji5ul9QSBRR52j54fT9xHAxL-rboumHs",
            "y4q20v0qNc8RtYVQVsNwm_Am1z0hx9xNjXjcNGKgH0ryMFWIGTxN_eexl_cc2g9leJMpzIqwBTUNy90yW0VlPUnWtrtP4g9Z4QeZrwM4",
            "r5HwVw_cxFger0iGhx-4bLXksarwRP3nDtnAb2syjBdYiJ9IirZ9L6rKK_tXD5cuaBwcZwsJ1ENDQ1VZzSeVYL5gpVEq_5fvmNObCDnEzw",
            "2J5nlC4PCF6NLrEsJvgXXTc_iQPX6mt30PCluL8vMCaTrpu5QvjtEcitLbd-mhLPiQh4V6nGbzLhDWZH3NXsfPcuVdASydJuRtqdazMhyfU",
            "T5QIIuRI38m6q0ZERuaTrNhGfhPVI2qpkguHNqJZNJiTXaAYv8_6ubjjnEUAZMCLkHja5MVO0l7EQLaEr9-8hH0PA-UvLNUasYUYDZQb0Jou",
            "9uGX6TgvOZnUF2158KJTEys_Ho9gNlDA2gC_im-Ag8uiULRjuYMJb4AzvFhonTqLVrUp6uncWXKcC2l1vaQ6ZYC2eZg-pIQtcizQGhx8NTEGsw",
            "rhZgQ-PQM96a857ECp8DgsSQuYLHkl7wKNGwD_ro61fFmNh0O6q2fNPuT4sQaGkK6m6l1yiGAkxUFZLvOplz60xGMjByBebH2FO4Jzi0-RLd4q8",
            "mb64LyC2TPOmtKtT0x5KgCiWmGxpTG1zwkaYez2-ahFNigLkH6HIsA8IU2ixv7hexJ9ER2EYz4PGuWMyyr6HAsbI2sE2mTckP5UIje-cF2i_mJFI",
            "4NoeQWukzqHqmIy9fb9Cow-Ll0OIvdUumMXO1kUed5DJguf4KoThpTnZstaDaS1XC52_-G5EOZbWHt-S4wMCJKq9v_sPqa3ICTxVqQw1ngqWktOlpw",
            "qPezqtNCH6bINVKJLULIEhf0nL5pQZRuikWJ1mta7L064fxX3kB0FDfWbhPp1EtzEH9LJY3FAxw_Uk0lU1FKVrfEwC6xsoKYe_XyovWzUak2N-FIXKE",
            "WxbGFiQOGOAKUQ9V7ME9tCibApQtzQ6h3Tq6FImQlbQeXBLhMKlJBLaB4EbozyrkKu31Ly-kYP4bjnTYN-brndzUwjcd8qpKur9P9KEKMdcwpJV5l-4t",
            "ZsTdFy5oVeZ96DHX8BP12kYnCCnoeX-rOXR-iWsWQF3NujWNsTipkuL4RcBHPSGQ4CI5VGjTe79_-qnWAWxsRR34nD3FH80N2c7Pq7YrISejB9GQeiaLNg",
            "jsorKAAeaexaPv_ACPQJDpgBEWhEMMztyhtPO1Ik3u9qijAmJEe21foDXGnZ2v8-cW_6kHA5bJj5atZ3beQ3NN56OgCsuZeHGJdQwW3UxjlodeRxQ-qwHrQ",
            "06gzf1gMtshvicAjfWlYih8bT0ZZ4xw8Sc5rO-UtRosyDJTzrUmBxgQGDu56RmJaH1sOQL6tu7Cg66MR0iYR6nOh6i1O90t_PgiwU9yBTEccnkmXV3qjpF0U",
            "2ZbXCb4M2xMexs1jiWGTou6zjJzxJp3kjfYc-Th_pqixIRK9EW0vHE648flV4UG1Qs791E1kA4MIWqoVoMccKKX0-RzHBlRnpMegs1pG8M8_Bfzzu8xAK63M5A",
            "tfJkxizYBpcirxxhj45_YPtTv30hXN15oaUvJvUGcUDCa8EKImVFU6d9MgnGGTwaRKYIq-CbMZrh3PY9O_DjZ81Y1ukQlzSKXOBwV3JBQNB0ndLo12r_XXUaFPg",
            "-5MpP_i_5PLst6d2QOsl4-oIU5QCgITDCzkyhhb2VHZQO6Qk4p0fsGzAg3znuikSeL-xIdAUrcpm9pM-cBGxroAALUgJnqLkI35WhiF32Zw6IV4_oYrl42rYH4q_",
            "wAHIWJEsmefqec6mnGNw5d9yr4QAph-8gAkZmc6pB7rhWDLnje4nIvFdcD3G4NgfOkghuo_6-jieoKzMTNrdWWyFyrq-bgp7F_OhvOCFFGjM43KhRhIDx5qsfUXXRw",
            "FjqUGdzYhkB9kne_GzHRLXTry8158WMz95YSwuQZQjhsEP9eTm-YFYGtvfwOsTCF7-_qyxsYtcXQs6NuJYyaEzwRgbjsGQPsRZz_dGncBHvdzQ9UPVIweNbdgfBGuRs",
            "vC8L1lCAPWPh5dzrKrzxlxmaHZdQLNJRyoZANjGlSYWz9ZW-yiJ8QnDQoUwI3WTrjIB5QpkapSqCbBrMZKkuGkK--2T8sgV_bPl0Nkue-oIlQfYywbCM73hApEjcCBxG",
            "XQi35b8zsvEg_FW64CuQfPUS4y_hKT-UvLB90hW0BoaoMRVCFSNJwdqN_xlOBKDfZ3UaF_0OCqIjZq6pOgER0RUgmnx9YaZ3VAwCZ_Y6NbgSGfO8ytv0QDp2LfdbZFKtbw",
            "pvS-qpn6XVs9Q-CXYWwUbjSGnVFHsO9R5zq0f5Ls11syaf5zJ8cct-R48QgEJignHMUTCu8ClTjnXE4iE4Bm5oYYEeY97sqj4P_pjrM5SjVZ2hGD40EoV0OFLNo-IdoDJf0",
            "MJAsZmWx9mPndWeoj4L5HmbebQEPngF-6FjvMVAO3q8CbO1943HMOxo5myfYMAXlAX7H0gsQV0Kk-rTrIVvAlmkRA5eElK7_ztz75tSG7sg7hXA-nkuXOWiPgmw-4ATmZlek",
            "hj0UQxVn8H70Qb6GxuEDRcuDcsLwZKXJUP5fGqoYl1fm53Msa9qQ4O5cGMp9p2yiylYg7Ys-zHPpHxCiBx-tuU-bFUvriaCR3eIMniM6RLQ1gnqB7D7dMwe1TddjPES8d5ysyA",
            "8KXkqEc9Q3xPmU6VyeUaXjhvWZGSLgLAaH-m2Ubp_gmN-vlduhkXzxciRHeT7jkUHvMt2JczD_gY4sn8Pn9-RPoy11VpDRzXDr9I-OMzNwqzt0OLnfBTDvBWPojTJTVrFRDaLzs",
            "idxFzEtY_FQ-dcY2MJ7WuIt_UmafJApFW1vPWAP6LnEIm2TahVqDGs93wgQs4kewWeBsVhjmtLCMH7IcNyavDa0yc9bzd5EhwHZwmVuc7TVo6TmsN3MiMg57Spq78Ur-2sCrwpwX",
            "wDkNMUPUFESxc0Kz0jqUrm6BnPu9OYOJn8VSMc_YjamfRkJi5CSHWZmv-Ps__dg5dwOR1gzIg56z4SUfyBSR9nVpF34DpgoFEs3E69B8GdnjANpTY6swRA2hGnue2jBzRTQrWjwYbA",
        ];
        const INPUT: &[u8] = &[60; BLOCK_SIZE * 2];

        for (i, expected) in PRECALC.iter().enumerate() {
            let cipher = crypto_manager
                .deterministic_encrypt(&INPUT[..i], None)
                .unwrap();
            assert_eq!(from_base64(expected).unwrap(), cipher);
        }

        Ok(())
    }
}
