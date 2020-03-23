extern crate openssl;

use openssl::pkcs5::scrypt;
use openssl::error::ErrorStack;

// FIXME: have our own error
pub fn derive_key(salt: &str, password: &str) -> Result<Box<[u8]>, ErrorStack> {
    let salt = salt.as_bytes();
    let password = password.as_bytes();
    let mut key: Box<[u8]> = Box::new([0; 190]);
    match scrypt(password, salt, 16384, 8, 1, 0, &mut *key) {
        Ok(_res) => Ok(key),
        Err(e) => Err(e),
    }
}
