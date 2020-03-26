// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

use etesync::{
    crypto,
    crypto::{
        AsymmetricKeyPair,
        AsymmetricCryptoManager,
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
    let keypair = AsymmetricKeyPair::generate_keypair().unwrap();
    let pkey = &keypair.get_pkey().unwrap();
    let crypto_manager = AsymmetricCryptoManager::new(&keypair);

    let message = vec![1, 2, 4, 5];
    let ciphertext = crypto_manager.encrypt(&pkey, &message).unwrap();
    let decrypted = crypto_manager.decrypt(&ciphertext).unwrap();
    assert_eq!(&message, &decrypted);
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
