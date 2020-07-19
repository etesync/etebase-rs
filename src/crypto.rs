// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::convert::TryInto;

use sodiumoxide::crypto::pwhash::argon2id13;

use super::error::{
    Error,
    Result,
};

macro_rules! to_enc_error {
    ($x:expr, $msg:tt) => {
        ($x).or(Err(Error::Encryption($msg)))
    }
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
