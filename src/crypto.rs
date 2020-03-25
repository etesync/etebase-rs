extern crate openssl;
extern crate hmac;
extern crate sha2;

use sha2::Sha256;
use hmac::{Hmac, Mac};

use super::error::{Result, Error};

use openssl::{
    pkcs5::scrypt,
    rand,
    rsa::{
        Rsa,
        Padding,
    },
    symm::{encrypt, decrypt, Cipher},
};

pub const CURRENT_VERSION: u8 = 2;

type HmacSha256 = Hmac<Sha256>;

pub fn derive_key(salt: &str, password: &str) -> Result<Box<[u8]>> {
    let salt = salt.as_bytes();
    let password = password.as_bytes();
    let mut key: Box<[u8]> = Box::new([0; 190]);
    scrypt(password, salt, 16384, 8, 1, 0, &mut *key)?;

    Ok(key)
}

pub fn gen_uid() -> Result<String> {
    let mut bytes = [0; 32];
    rand::rand_bytes(&mut bytes)?;

    Ok(hex::encode(bytes))
}

pub fn memcmp(a: &[u8], b: &[u8]) -> bool {
    openssl::memcmp::eq(&a, &b)
}

fn hmac256(salt: &[u8], key: &[u8], extra: Option<&[u8]>) -> Result<Vec<u8>> {
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
    cipher_key: Vec<u8>,
    hmac_key: Vec<u8>,
}

impl CryptoManager {
    pub fn new(key: &[u8], salt: &str, version: u8) -> Result<CryptoManager> {
        let key = match version {
            1 => key.to_vec(),
            2 => hmac256(salt.as_bytes(), key, None)?,
            _ => return Err(Error::from("Version mismatch")),
        };

        CryptoManager::from_derived_key(&key, version)
    }

    pub fn from_derived_key(derived: &[u8], version: u8) -> Result<CryptoManager> {
        let cipher_key = hmac256(b"aes", derived, None)?;
        let hmac_key = hmac256(b"hmac", derived, None)?;

        Ok(CryptoManager {
            version,
            cipher_key,
            hmac_key,
        })
    }

    pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_256_cbc();
        let mut iv = [0; 16];
        rand::rand_bytes(&mut iv)?;
        let ciphertext = encrypt(cipher, &self.cipher_key, Some(&iv), message)?;

        let mut ret = iv.to_vec();
        ret.extend(ciphertext);
        Ok(ret)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_256_cbc();
        let iv = &ciphertext[0..16];
        let ciphertext = &ciphertext[16..];
        let message = decrypt(cipher, &self.cipher_key, Some(&iv), ciphertext)?;

        Ok(message)
    }

    pub fn hmac(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.version {
            1 => hmac256(&self.hmac_key, data, None),
            2 => hmac256(&self.hmac_key, data, Some(&[self.version])),
            _ => return Err(Error::from("Version mismatch")),
        }
    }
}

#[derive(Clone)]
pub struct AsymmetricKeyPair {
    rsa: Rsa<openssl::pkey::Private>,
}

impl AsymmetricKeyPair {
    pub fn generate_keypair() -> Result<AsymmetricKeyPair> {
        let rsa = Rsa::generate(3072)?;
        Ok(AsymmetricKeyPair {
            rsa,
        })
    }

    pub fn from_der(skey: &[u8], _pkey: &[u8]) -> Result<AsymmetricKeyPair> {
        // FIXME: Hack. For some reason the from_der variant doesn't work, but moving to PEM does.
        let pem = format!("-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----", base64::encode(skey));
        let rsa = Rsa::private_key_from_pem(&pem.as_bytes())?;
        Ok(AsymmetricKeyPair {
            rsa,
        })
    }

    pub fn get_skey(&self) -> Result<Vec<u8>> {
        Ok(self.rsa.private_key_to_der()?)
    }

    pub fn get_pkey(&self) -> Result<Vec<u8>> {
        Ok(self.rsa.public_key_to_der()?)
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

    pub fn encrypt(&self, pkey: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let rsa = Rsa::public_key_from_der(pkey)?;
        let mut buf = vec![0; rsa.size() as usize];
        let result_len = rsa.public_encrypt(message, &mut buf, Padding::PKCS1_OAEP)?;
        buf.truncate(result_len);

        Ok(buf)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let rsa = &self.keypair.rsa;
        let mut buf = vec![0; rsa.size() as usize];
        let result_len = rsa.private_decrypt(ciphertext, &mut buf, Padding::PKCS1_OAEP)?;
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
