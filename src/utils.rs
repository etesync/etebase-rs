// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

mod sodium_padding;

use sodiumoxide::base64;

use super::error::{
    Error,
    Result,
};

#[doc(hidden)]
#[macro_export]
macro_rules! try_into {
    ($x:expr) => {
        ($x).try_into().or(Err(Error::ProgrammingError("Try into failed")))
    }
}

pub type StrBase64 = str;
pub type StringBase64 = String;

/// The size of a symmetric encryption key
pub const SYMMETRIC_KEY_SIZE: usize = 32; // sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
/// The size of a symmetric encryption tag
pub const SYMMETRIC_TAG_SIZE: usize = 16; // sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
/// The size of a symmetric encryption nonce
pub const SYMMETRIC_NONCE_SIZE: usize = 24; // sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

/// Return a buffer filled with cryptographically random bytes
///
/// # Arguments:
/// * `size` - the size of the returned buffer (in bytes)
pub fn randombytes(size: usize) -> Vec<u8> {
    sodiumoxide::randombytes::randombytes(size)
}

/// Return a buffer filled with deterministically cryptographically random bytes
///
/// This function is similar to [randombytes] but always returns the same data for the same seed.
/// Useful for testing purposes.
///
/// # Arguments:
/// * `seed` - the seed to generate the random data from
/// * `size` - the size of the returned buffer (in bytes)
pub fn randombytes_deterministic(size: usize, seed: &[u8; 32]) -> Vec<u8> {
    // Not exactly like the sodium randombytes_deterministic but close enough
    let nonce = sodiumoxide::crypto::stream::xchacha20::Nonce(*b"LibsodiumDRG\0\0\0\0\0\0\0\0\0\0\0\0");
    let key = sodiumoxide::crypto::stream::xchacha20::Key(*seed);

    sodiumoxide::crypto::stream::xchacha20::stream(size, &nonce, &key)
}

/// A constant-time comparison function
///
/// Use this when comparing secret data in order to prevent side-channel attacks.
///
/// # Arguments:
/// * `x` - the first buffer
/// * `y` - the second buffer
pub fn memcmp(x: &[u8], y: &[u8]) -> bool {
    sodiumoxide::utils::memcmp(x, y)
}

/// Convert a Base64 URL encoded string to a buffer
///
/// # Arguments:
/// * `string` - the Base64 URL encoded string
pub fn from_base64(string: &StrBase64) -> Result<Vec<u8>> {
    match base64::decode(string, base64::Variant::UrlSafeNoPadding) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Err(Error::Base64("Failed decoding base64 string")),
    }
}

/// Convert a buffer to a Base64 URL encoded string
///
/// # Arguments:
/// * `bytes` - the buffer to convert
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

/// Return the recommended padding length for a buffer of specific length
///
/// Padding data before encrypting it is important for preventing fingerprint analysis attacks.
/// This function aims to return the optimal balance between space efficiently and fingerprint
/// resistance. The returned values may change between versions.
///
/// # Arguments:
/// * `length` - the length of the buffer to pad
pub fn get_padding(length: u32) -> u32 {
    // Use the padme padding scheme for efficiently
    // https://www.petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf

    // We want a minimum pad size of 4k
    if length < (1 << 14) {
        let size = (1 << 10) - 1;
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
pub(crate) fn buffer_pad_small(buf: &[u8]) -> Result<Vec<u8>> {
    let len = buf.len();
    let padding = len + 1;

    buffer_pad_fixed(buf, padding)
}

pub(crate) fn buffer_pad(buf: &[u8]) -> Result<Vec<u8>> {
    let len = buf.len();
    let padding = get_padding(len as u32) as usize;

    buffer_pad_fixed(buf, padding)
}

pub(crate) fn buffer_unpad(buf: &[u8]) -> Result<Vec<u8>> {
    let len = buf.len();

    // We pass the buffer's length as the block size because due to padme there's always some variable-sized padding.
    buffer_unpad_fixed(buf, len)
}

pub(crate) fn buffer_pad_fixed(buf: &[u8], blocksize: usize) -> Result<Vec<u8>> {
    let len = buf.len();
    let missing = blocksize - (len % blocksize);
    let padding = len + missing;
    let mut ret = vec![0; padding];
    ret[..len].copy_from_slice(buf);

    sodium_padding::pad(&mut ret[..], len, blocksize).map_err(|_| Error::Padding("Failed padding"))?;

    Ok(ret)
}

pub(crate) fn buffer_unpad_fixed(buf: &[u8], blocksize: usize) -> Result<Vec<u8>> {
    let len = buf.len();
    if len == 0 {
        return Ok(vec![0; 0]);
    }

    let mut buf = buf.to_vec();

    let new_len = sodium_padding::unpad(&mut buf[..], len, blocksize).map_err(|_| Error::Padding("Failed unpadding"))?;
    buf.truncate(new_len);
    Ok(buf)
}

/// A trait for serializing and deserializing to MsgPack
pub trait MsgPackSerilization {
    /// The type of the struct implementing this trait
    type Output;

    /// Convert self to a msgpack encoded buffer
    fn to_msgpack(&self) -> Result<Vec<u8>>;

    /// Create the struct from a MsgPack encoded buffer
    ///
    /// # Arguments:
    /// * `data` - the MsgPack buffer
    fn from_msgpack(data: &[u8]) -> Result<Self::Output>;
}
