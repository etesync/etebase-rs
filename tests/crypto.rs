// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::convert::TryInto;

use etebase::crypto;

use etebase::utils::from_base64;

mod common;

use common::{
    PASSWORD,
    KEY_BASE64,
    SALT_BASE64,
    get_encryption_key
};


#[test]
fn derive_key() {
    etebase::init().unwrap();

    let derived = crypto::derive_key(&from_base64(SALT_BASE64).unwrap(), PASSWORD).unwrap();
    let expected = get_encryption_key();
    assert_eq!(&derived[..], &expected[..]);
}

#[test]
fn crypto_manager() {
    etebase::init().unwrap();

    let key = from_base64(KEY_BASE64).unwrap();
    let context = b"Col     ";
    let crypto_manager = crypto::CryptoManager::new(&key[0..32].try_into().unwrap(), context, etebase::CURRENT_VERSION).unwrap();
    let subkey = crypto_manager.derive_subkey(&[0; 32]).unwrap();

    assert_eq!(subkey, from_base64("4w-VCSTETv26JjVlVlD2VaACcb6aQSD2JbF-e89xnaA").unwrap());

    let hash = crypto_manager.calculate_mac(&[0; 32]).unwrap();
    assert_eq!(hash, from_base64("bz6eMZdAkIuiLUuFDiVwuH3IFs4hYkRfhzang_JzHr8").unwrap());

    let hash = crypto_manager.calculate_hash(&[0; 32]).unwrap();
    assert_eq!(hash, from_base64("iesNaoppHa4s0V7QNpkxzgqUnsr6XD-T-BIYM2RuFcM").unwrap());

    let clear_text = b"This Is Some Test Cleartext.";
    let cipher = crypto_manager.encrypt(clear_text, None).unwrap();
    let decrypted = crypto_manager.decrypt(&cipher, None).unwrap();
    assert_eq!(clear_text, &decrypted[..]);

    let clear_text = b"This Is Some Test Cleartext.";
    let (tag, cipher) = crypto_manager.encrypt_detached(clear_text, None).unwrap();
    let tag: &[u8; 16] = &tag[..].try_into().unwrap();
    let decrypted = crypto_manager.decrypt_detached(&cipher, tag, None).unwrap();
    assert_eq!(clear_text, &decrypted[..]);

    crypto_manager.verify(&cipher, tag, None).unwrap();
}

#[test]
fn login_crypto_manager() {
    etebase::init().unwrap();

    let login_crypto_manager = crypto::LoginCryptoManager::keygen(&[0; 32]).unwrap();

    let msg = b"This Is Some Test Cleartext.";
    let signature = login_crypto_manager.sign_detached(msg).unwrap();
    let pubkey = login_crypto_manager.get_pubkey();
    assert!(login_crypto_manager.verify_detached(msg, &signature, (&pubkey[..]).try_into().unwrap()).unwrap());
}
