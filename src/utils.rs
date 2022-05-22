// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::convert::TryInto;

use sodiumoxide::{
    base64,
    padding::{pad, unpad},
};

use super::error::{Error, Result};

pub type StrBase64 = str;
pub type StringBase64 = String;

/// The size of the salt added to the password to derive the symmetric encryption key
pub const SALT_LENGTH: usize = 16; // sodium.crypto_pwhash_argon2id_SALTBYTES
/// The size of the private encryption key
pub const PRIVATE_KEY_SIZE: usize = 32; // sodium.crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;
/// The size of a symmetric encryption key
pub const SYMMETRIC_KEY_SIZE: usize = 32; // sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
/// The size of a symmetric encryption tag
pub const SYMMETRIC_TAG_SIZE: usize = 16; // sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
/// The size of a symmetric encryption nonce
pub const SYMMETRIC_NONCE_SIZE: usize = 24; // sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

/// Returns a buffer filled with cryptographically random bytes.
///
/// # Examples
///
/// ```
/// use etebase::utils::randombytes;
///
/// let a = randombytes(5);
/// assert_eq!(5, a.len());
///
/// let b = randombytes(0);
/// assert!(b.is_empty());
/// ```
pub fn randombytes(size: usize) -> Vec<u8> {
    sodiumoxide::randombytes::randombytes(size)
}

/// A version of [`randombytes`] that returns a fixed-size array instead of a Vec.
///
/// # Examples
///
/// ```
/// use etebase::utils::randombytes_array;
///
/// // Explicitly specifying the length as a type generic
/// let a = randombytes_array::<5>();
///
/// // Letting the length be inferred from the result type
/// let b: [u8; 10] = randombytes_array();
/// ```
pub fn randombytes_array<const N: usize>() -> [u8; N] {
    sodiumoxide::randombytes::randombytes(N)
        .try_into()
        .expect("randombytes() returned a Vec with wrong size")
}

/// Return a buffer filled with deterministically cryptographically random bytes
///
/// This function is similar to [`randombytes`] but always returns the same data for the same seed.
/// Useful for testing purposes.
///
/// # Arguments:
/// * `seed` - the seed to generate the random data from
/// * `size` - the size of the returned buffer (in bytes)
///
/// # Examples
///
/// ```
/// use etebase::utils::randombytes_deterministic;
///
/// let seed = [42; 32];
///
/// // Equal seeds produce equal sequences, regardless of length
/// let a = randombytes_deterministic(10, &seed);
/// let b = randombytes_deterministic(5, &seed);
///
/// assert_eq!(a[..5], b);
///
/// // Different seeds produce different sequences
/// let c = randombytes_deterministic(10, &[0; 32]);
///
/// assert_ne!(a, c);
/// assert_eq!(c, &[5, 67, 208, 128, 105, 110, 24, 70, 104, 100]);
/// ```
pub fn randombytes_deterministic(size: usize, seed: &[u8; 32]) -> Vec<u8> {
    // Not exactly like the sodium randombytes_deterministic but close enough
    let nonce =
        sodiumoxide::crypto::stream::xchacha20::Nonce(*b"LibsodiumDRG\0\0\0\0\0\0\0\0\0\0\0\0");
    let key = sodiumoxide::crypto::stream::xchacha20::Key(*seed);

    sodiumoxide::crypto::stream::xchacha20::stream(size, &nonce, &key)
}

/// A constant-time comparison function. Returns `true` if `x` and `y` are equal.
///
/// Use this when comparing secret data in order to prevent side-channel attacks.
///
/// # Examples
///
/// ```
/// use etebase::utils::memcmp;
///
/// fn validate_password(input: &[u8]) -> Result<(), ()> {
///     let password = b"hunter2";
///
///     if memcmp(input, password) {
///         Ok(())
///     } else {
///         Err(())
///     }
/// }
///
/// assert_eq!(Err(()), validate_password(b"letmein"));
/// assert_eq!(Err(()), validate_password(b""));
/// assert_eq!(Ok(()), validate_password(b"hunter2"));
/// ```
pub fn memcmp(x: &[u8], y: &[u8]) -> bool {
    sodiumoxide::utils::memcmp(x, y)
}

/// Converts a Base64 URL encoded string to a Vec of bytes.
///
/// # Examples
///
/// ```
/// use etebase::utils::from_base64;
///
/// let data = "SGVsbG8_IFdvcmxkIQ";
/// let decoded = from_base64(data);
///
/// assert_eq!(Ok(b"Hello? World!".to_vec()), decoded);
///
/// assert_eq!(Ok(b"".to_vec()), from_base64(""));
/// ```
pub fn from_base64(string: &StrBase64) -> Result<Vec<u8>> {
    match base64::decode(string, base64::Variant::UrlSafeNoPadding) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Err(Error::Base64("Failed decoding base64 string")),
    }
}

/// Convert a buffer to a Base64 URL encoded string
///
/// # Examples
///
/// ```
/// use etebase::utils::to_base64;
///
/// let data = b"Hello? World!";
/// let encoded = to_base64(data);
///
/// assert_eq!(Ok("SGVsbG8_IFdvcmxkIQ"), encoded.as_deref());
///
/// assert_eq!(Ok(""), to_base64(b"").as_deref());
/// ```
pub fn to_base64(bytes: &[u8]) -> Result<StringBase64> {
    Ok(base64::encode(bytes, base64::Variant::UrlSafeNoPadding))
}

/// Fisher–Yates shuffle - an unbiased shuffler
///
/// Shuffles the passed slice in-place and returns the new indices of all input items.
///
/// # Examples
///
/// ```no_compile
/// let mut data = vec!["foo", "bar", "baz"];
///
/// let ret = shuffle(&mut data);
/// // Let's assume the data was randomly shuffled like this:
/// # data = vec!["bar", "baz", "foo"];
/// assert_eq!(data, &["bar", "baz", "foo"]);
///
/// // The first element (foo) is now at index 2, the second is at index 0, the third is at index 1
/// assert_eq!(ret, &[2, 0, 1]);
/// ```
pub(crate) fn shuffle<T>(a: &mut [T]) -> Vec<usize> {
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

    (length + bit_mask) & !bit_mask
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

    pad(&mut ret[..], len, blocksize).map_err(|_| Error::Padding("Failed padding"))?;

    Ok(ret)
}

pub(crate) fn buffer_unpad_fixed(buf: &[u8], blocksize: usize) -> Result<Vec<u8>> {
    let len = buf.len();
    if len == 0 {
        return Ok(vec![0; 0]);
    }

    let mut buf = buf.to_vec();

    let new_len =
        unpad(&buf[..], len, blocksize).map_err(|_| Error::Padding("Failed unpadding"))?;
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
