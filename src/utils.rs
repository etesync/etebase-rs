// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use sodiumoxide::base64;

use block_padding::{Iso7816, Padding};

use super::error::{
    Error,
    Result,
};

#[macro_export]
macro_rules! try_into {
    ($x:expr) => {
        ($x).try_into().or(Err(Error::TryInto("Try into failed")))
    }
}

pub const SYMMETRIC_KEY_SIZE: usize = 32; // sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
pub const SYMMETRIC_TAG_SIZE: usize = 16; // sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
pub const SYMMETRIC_NONCE_SIZE: usize = 24; // sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

pub fn randombytes(size: usize) -> Vec<u8> {
    sodiumoxide::randombytes::randombytes(size)
}

pub fn from_base64(string: &str) -> Result<Vec<u8>> {
    match base64::decode(string, base64::Variant::UrlSafeNoPadding) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Err(Error::Base64("Failed decoding base64 string")),
    }
}

pub fn to_base64(bytes: &[u8]) -> Result<String> {
    Ok(base64::encode(bytes, base64::Variant::UrlSafeNoPadding))
}

pub fn get_padding(length: u32) -> u32 {
    // Use the padme padding scheme for efficiently
    // https://www.petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf

    // We want a minimum pad size of 4k
    if length < (1 << 18) {
        let size = (1 << 12) - 1;
        // We add 1 so we always have some padding
        return (length | size) + 1;
    }

    let e = (length as f64).log2().floor();
    let s = (e.log2().floor() as u32) + 1;
    let last_bits = (e as u32) - s;
    let bit_mask = (1 << last_bits) - 1;
    return (length + bit_mask) & !bit_mask;
}

pub fn buffer_pad(buf: &[u8]) -> Result<Vec<u8>> {
    let len = buf.len();
    let padding = get_padding(len as u32) as usize;
    let mut ret = vec![0; padding];
    ret[..len].copy_from_slice(buf);

    Iso7816::pad_block(&mut ret[..], len)?;

    Ok(ret)
}

pub fn buffer_unpad(buf: &[u8]) -> Result<Vec<u8>> {
    let len = buf.len();
    let mut buf = buf.to_vec();

    if len == 0 {
        return Ok(vec![0; 0]);
    }

    // We pass the buffer's length as the block size because due to padme there's always some variable-sized padding.
    Ok(Iso7816::unpad(&mut buf[..])?.to_vec())
}
