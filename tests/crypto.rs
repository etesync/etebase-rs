use etesync::{
    crypto,
    crypto::{
        AsymmetricKeyPair,
        CryptoManager,
    },
};

use base64;

const USER: &str = "test@localhost";
const PASSWORD: &str = "SomePassword";
const KEY_BASE64: &str = "Gpn6j6WJ/9JJbVkWhmEfZjlqSps5rwEOzjUOO0rqufvb4vtT4UfRgx0uMivuGwjF7/8Y1z1glIASX7Oz/4l2jucgf+lAzg2oTZFodWkXRZCDmFa7c9a8/04xIs7koFmUH34Rl9XXW6V2/GDVigQhQU8uWnrGo795tupoNQMbtB8RgMX5GyuxR55FvcybHpYBbwrDIsKvXcBxWFEscdNU8zyeq3yjvDo/W/y24dApW3mnNo7vswoL2rpkZj3dqw==";

#[test]
fn derive_key() {
    let derived = crypto::derive_key(USER, PASSWORD).unwrap();
    let derived64 = base64::encode(derived);
    assert_eq!(derived64, KEY_BASE64);
}

#[test]
fn generate_keypair() {
    let _keypair = AsymmetricKeyPair::generate_keypair().unwrap();
}

#[test]
fn symmetric_enc_v1() {
    let derived = base64::decode(KEY_BASE64).unwrap();
    let crypto_manager = CryptoManager::new(&derived, "TestSaltShouldBeJournalId", 1).unwrap();

    let cleartext = b"This Is Some Test Cleartext.";
    let ciphertext = crypto_manager.encrypt(cleartext).unwrap();
    assert_eq!(cleartext, &(crypto_manager.decrypt(&ciphertext).unwrap()[..]));

    let expected = base64::decode("Lz+HUFzh1HdjxuGdQrBwBG1IzHT0ug6mO8fwePSbXtc=").unwrap();
    let hmac = crypto_manager.hmac(b"Some test data").unwrap();
    assert_eq!(expected, hmac);
}

#[test]
fn symmetric_enc_v2() {
    let derived = base64::decode(KEY_BASE64).unwrap();
    let crypto_manager = CryptoManager::new(&derived, "TestSaltShouldBeJournalId", 2).unwrap();

    let cleartext = b"This Is Some Test Cleartext.";
    let ciphertext = crypto_manager.encrypt(cleartext).unwrap();
    assert_eq!(cleartext, &(crypto_manager.decrypt(&ciphertext).unwrap()[..]));

    let expected = base64::decode("XQ/A0gentOaE98R9wzf3zEIAHj4OH1GF8J4C6JiJupo=").unwrap();
    let hmac = crypto_manager.hmac(b"Some test data").unwrap();
    assert_eq!(expected, hmac);
}
