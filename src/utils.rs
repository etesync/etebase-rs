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

pub type StrBase64 = str;
pub type StringBase64 = String;

pub const SYMMETRIC_KEY_SIZE: usize = 32; // sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
pub const SYMMETRIC_TAG_SIZE: usize = 16; // sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
pub const SYMMETRIC_NONCE_SIZE: usize = 24; // sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

pub fn randombytes(size: usize) -> Vec<u8> {
    sodiumoxide::randombytes::randombytes(size)
}

pub fn randombytes_deterministic(size: usize, seed: &[u8; 32]) -> Vec<u8> {
    // Not exactly like the sodium randombytes_deterministic but close enough
    let nonce = sodiumoxide::crypto::stream::xchacha20::Nonce(*b"LibsodiumDRG\0\0\0\0\0\0\0\0\0\0\0\0");
    let key = sodiumoxide::crypto::stream::xchacha20::Key(*seed);

    sodiumoxide::crypto::stream::xchacha20::stream(size, &nonce, &key)
}

pub fn memcmp(x: &[u8], y: &[u8]) -> bool {
    sodiumoxide::utils::memcmp(x, y)
}

pub fn from_base64(string: &StrBase64) -> Result<Vec<u8>> {
    match base64::decode(string, base64::Variant::UrlSafeNoPadding) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Err(Error::Base64("Failed decoding base64 string")),
    }
}

pub fn to_base64(bytes: &[u8]) -> Result<StringBase64> {
    Ok(base64::encode(bytes, base64::Variant::UrlSafeNoPadding))
}
// Fisher–Yates shuffle - an unbiased shuffler
// The returend indices of where item is now.
// So if the first item moved to position 3: ret[0] = 3
pub(crate) fn shuffle<T>(a: &mut Vec<T>) -> Vec<usize> {
    let len = a.len();
    let mut shuffled_indices: Vec<usize> = (0..len).collect();

    for i in 0..len {
        let j = i + sodiumoxide::randombytes::randombytes_uniform((len - i) as u32) as usize;
        a.swap(i, j);
        shuffled_indices.swap(i, j);
    }

    let mut ret = vec![0; len];
    for i in 0..len {
        ret[shuffled_indices[i]] = i;
    }
    ret
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

// FIXME: we should properly pad the meta and probably change these functions
pub(crate) fn buffer_pad_meta(buf: &[u8]) -> Result<Vec<u8>> {
    let len = buf.len();
    let padding = len + 1;
    let mut ret = vec![0; padding];
    ret[..len].copy_from_slice(buf);

    Iso7816::pad_block(&mut ret[..], len)?;

    Ok(ret)
}

pub(crate) fn buffer_pad(buf: &[u8]) -> Result<Vec<u8>> {
    let len = buf.len();
    let padding = get_padding(len as u32) as usize;
    let mut ret = vec![0; padding];
    ret[..len].copy_from_slice(buf);

    Iso7816::pad_block(&mut ret[..], len)?;

    Ok(ret)
}

pub(crate) fn buffer_unpad(buf: &[u8]) -> Result<Vec<u8>> {
    let len = buf.len();
    let mut buf = buf.to_vec();

    if len == 0 {
        return Ok(vec![0; 0]);
    }

    // We pass the buffer's length as the block size because due to padme there's always some variable-sized padding.
    Ok(Iso7816::unpad(&mut buf[..])?.to_vec())
}

pub trait MsgPackSerilization {
    type Output;

    fn to_msgpack(&self) -> Result<Vec<u8>>;
    fn from_msgpack(data: &[u8]) -> Result<Self::Output>;
}
