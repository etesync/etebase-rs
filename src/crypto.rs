extern crate openssl;

use openssl::pkcs5::scrypt;

pub fn derive_key(salt: &str, password: &str) -> Result<Box<[u8]>, ()> {
    let salt = salt.as_bytes();
    let password = password.as_bytes();
    let mut key: Box<[u8]> = Box::new([0; 190]);
    // FIXME: we shouldn't be unwrapping!
    scrypt(password, salt, 16384, 8, 1, 0, &mut *key).unwrap();
    Ok(key)
}
