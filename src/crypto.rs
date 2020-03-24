extern crate openssl;
extern crate hmac;
extern crate sha2;

use sha2::Sha256;
use hmac::{Hmac, Mac};

use openssl::{
    pkcs5::scrypt,
    rand,
    rsa::{
        Rsa,
        Padding,
    },
    symm::{encrypt, decrypt, Cipher},
    error::ErrorStack,
};

pub const CURRENT_VERSION: u8 = 2;

type HmacSha256 = Hmac<Sha256>;

// FIXME: don't use unwrap, have proper error handling - won't work in C...
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

pub fn memcmp(a: &[u8], b: &[u8]) -> bool {
    openssl::memcmp::eq(&a, &b)
}

fn hmac256(salt: &[u8], key: &[u8], extra: Option<&[u8]>) -> Result<Vec<u8>, &'static str> {
    let mut mac = HmacSha256::new_varkey(salt)
        .expect("HMAC can take key of any size");
    mac.input(key);
    if let Some(extra) = extra {
        mac.input(extra);
    }
    let result = mac.result();
    let code_bytes = result.code();

    Ok(code_bytes.to_vec())
}

pub struct CryptoManager {
    pub version: u8,
    key: Vec<u8>,
    cipher_key: Vec<u8>,
    hmac_key: Vec<u8>,
}

impl CryptoManager {
    pub fn new(key: &[u8], salt: &str, version: u8) -> Result<CryptoManager, &'static str> {
        let key = match version {
            1 => key.to_vec(),
            2 => hmac256(salt.as_bytes(), key, None).unwrap(),
            _ => return Err("Version mismatch"),
        };

        CryptoManager::from_derived_key(&key, version)
    }

    pub fn from_derived_key(derived: &[u8], version: u8) -> Result<CryptoManager, &'static str> {
        let cipher_key = hmac256(b"aes", derived, None).unwrap();
        let hmac_key = hmac256(b"hmac", derived, None).unwrap();

        Ok(CryptoManager {
            version,
            key: key.to_vec(),
            cipher_key,
            hmac_key,
        })
    }

    pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, &'static str> {
        let cipher = Cipher::aes_256_cbc();
        let mut iv = [0; 16];
        rand::rand_bytes(&mut iv).unwrap();
        let ciphertext = encrypt(cipher, &self.cipher_key, Some(&iv), message);
        match ciphertext {
            Ok(ciphertext) => {
                let mut ret = iv.to_vec();
                ret.extend(ciphertext);
                Ok(ret)
            }
            Err(_e) => Err("Failed encrypting"),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let cipher = Cipher::aes_256_cbc();
        let iv = &ciphertext[0..16];
        let ciphertext = &ciphertext[16..];
        let message = decrypt(cipher, &self.cipher_key, Some(&iv), ciphertext);
        match message {
            Ok(message) => Ok(message),
            Err(_e) => Err("Failed decrypting"),
        }
    }

    pub fn hmac(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        match self.version {
            1 => hmac256(&self.hmac_key, data, None),
            2 => hmac256(&self.hmac_key, data, Some(&[self.version])),
            _ => return Err("Version mismatch"),
        }
    }
}

#[derive(Clone)]
pub struct AsymmetricKeyPair {
    rsa: Rsa<openssl::pkey::Private>,
}

impl AsymmetricKeyPair {
    pub fn generate_keypair() -> Result<AsymmetricKeyPair, ()> {
        let rsa = Rsa::generate(3072).unwrap();
        Ok(AsymmetricKeyPair {
            rsa,
        })
    }

    pub fn get_skey(&self) -> Result<Vec<u8>, &'static str> {
        Ok(self.rsa.private_key_to_der().unwrap())
    }

    pub fn get_pkey(&self) -> Result<Vec<u8>, &'static str> {
        Ok(self.rsa.public_key_to_der().unwrap())
    }
}

pub struct AsymmetricCryptoManager {
    keypair: AsymmetricKeyPair,
}

impl AsymmetricCryptoManager {
    pub fn new(keypair: &AsymmetricKeyPair) -> AsymmetricCryptoManager {
        AsymmetricCryptoManager {
            keypair: keypair.clone(),
        }
    }

    pub fn encrypt(&self, pkey: &[u8], message: &[u8]) -> Result<Vec<u8>, &'static str> {
        let rsa = Rsa::public_key_from_der(pkey).unwrap();
        let mut buf = vec![0; rsa.size() as usize];
        let result_len = rsa.public_encrypt(message, &mut buf, Padding::PKCS1_OAEP).unwrap();
        buf.truncate(result_len);

        Ok(buf)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let rsa = &self.keypair.rsa;
        let mut buf = vec![0; rsa.size() as usize];
        let result_len = rsa.private_decrypt(ciphertext, &mut buf, Padding::PKCS1_OAEP).unwrap();
        buf.truncate(result_len);

        Ok(buf)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac256_test() {
        let expected = base64::decode("9jlIFypuMTGBLjUFVvf0ZUA/GVuhhMPDF1cc3QG5QXM=").unwrap();
        let hmac = hmac256(b"Salt", b"SomeKey", None).unwrap();
        assert_eq!(hmac, expected);
    }
}
