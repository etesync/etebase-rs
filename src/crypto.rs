extern crate openssl;

use openssl::{
    pkcs5::scrypt,
    rsa::{
        Rsa,
    },
    error::ErrorStack,
};

// FIXME: have our own error type
pub fn derive_key(salt: &str, password: &str) -> Result<Box<[u8]>, ErrorStack> {
    let salt = salt.as_bytes();
    let password = password.as_bytes();
    let mut key: Box<[u8]> = Box::new([0; 190]);
    match scrypt(password, salt, 16384, 8, 1, 0, &mut *key) {
        Ok(_res) => Ok(key),
        Err(e) => Err(e),
    }
}

pub struct AsymmetricKeyPair {
    pub pkey: Vec<u8>,
    pub skey: Vec<u8>,
}

impl AsymmetricKeyPair {
    pub fn generate_keypair() -> Result<Box<AsymmetricKeyPair>, ()> {
        let rsa = Rsa::generate(3072).unwrap();
        // FIXME: Shouldn't unwrap
        Ok(Box::new(AsymmetricKeyPair {
            skey: rsa.private_key_to_der().unwrap(),
            pkey: rsa.public_key_to_der().unwrap(),
        }))
    }
}
