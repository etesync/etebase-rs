use etesync::{
    crypto,
    crypto::{
        AsymmetricKeyPair,
        CryptoManager,
    },
};

mod common;

use common::{
    USER,
    PASSWORD,
    get_encryption_key
};

use base64;


#[test]
fn derive_key() {
    let derived = crypto::derive_key(USER, PASSWORD).unwrap();
    let expected = get_encryption_key();
    assert_eq!(&derived[..], &expected[..]);
}

#[test]
fn generate_keypair() {
    let _keypair = AsymmetricKeyPair::generate_keypair().unwrap();
}

#[test]
fn symmetric_enc_v1() {
    let derived = get_encryption_key();
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
    let derived = get_encryption_key();
    let crypto_manager = CryptoManager::new(&derived, "TestSaltShouldBeJournalId", 2).unwrap();

    let cleartext = b"This Is Some Test Cleartext.";
    let ciphertext = crypto_manager.encrypt(cleartext).unwrap();
    assert_eq!(cleartext, &(crypto_manager.decrypt(&ciphertext).unwrap()[..]));

    let expected = base64::decode("XQ/A0gentOaE98R9wzf3zEIAHj4OH1GF8J4C6JiJupo=").unwrap();
    let hmac = crypto_manager.hmac(b"Some test data").unwrap();
    assert_eq!(expected, hmac);
}
