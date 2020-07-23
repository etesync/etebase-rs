// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::convert::TryInto;

use etebase::test_helpers::crypto;

use etebase::utils::from_base64;

#[allow(dead_code)]
mod common;

use common::USER;

#[test]
fn derive_key() {
    etebase::init().unwrap();

    let derived = crypto::derive_key(&from_base64(USER.salt).unwrap(), USER.password).unwrap();
    let expected = from_base64(USER.key).unwrap();
    assert_eq!(&derived[..], &expected[..]);
}

#[test]
fn crypto_manager() {
    etebase::init().unwrap();

    let key = from_base64(USER.key).unwrap();
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

    let mut crypto_mac = crypto_manager.crypto_mac().unwrap();
    crypto_mac.update(&[0; 4]).unwrap();
    assert_eq!(crypto_mac.finalize().unwrap(), from_base64("y5nYZ75gDUna4bnaAHobXUlgQoTKOnueNW_KCYxcAg4").unwrap());
}

#[test]
fn login_crypto_manager() {
    etebase::init().unwrap();

    let login_crypto_manager = crypto::LoginCryptoManager::keygen(&[0; 32]).unwrap();

    let msg = b"This Is Some Test Cleartext.";
    let signature = login_crypto_manager.sign_detached(msg).unwrap();
    let pubkey = login_crypto_manager.pubkey();
    assert!(login_crypto_manager.verify_detached(msg, &signature, (&pubkey[..]).try_into().unwrap()).unwrap());
}

#[test]
fn box_crypto_manager() {
    etebase::init().unwrap();

    let box_crypto_manager = crypto::BoxCryptoManager::keygen(None).unwrap();
    let box_crypto_manager2 = crypto::BoxCryptoManager::keygen(None).unwrap();

    let msg = b"This Is Some Test Cleartext.";
    let cipher = box_crypto_manager.encrypt(msg, (&box_crypto_manager2.pubkey()[..]).try_into().unwrap()).unwrap();
    let decrypted = box_crypto_manager2.decrypt(&cipher[..], (&box_crypto_manager.pubkey()[..]).try_into().unwrap()).unwrap();
    assert_eq!(decrypted, msg);
}

#[test]
fn crypto_mac() {
    etebase::init().unwrap();

    let key = from_base64(USER.key).unwrap();

    let mut crypto_mac = crypto::CryptoMac::new(None).unwrap();
    crypto_mac.update(&[0; 4]).unwrap();
    crypto_mac.update_with_len_prefix(&[0; 8]).unwrap();
    assert_eq!(crypto_mac.finalize().unwrap(), from_base64("P-Hpzo86RG6Ps4R1gGXmQrzmdJC2OotqqreKmB8G45A").unwrap());

    let mut crypto_mac = crypto::CryptoMac::new(Some(&key)).unwrap();
    crypto_mac.update(&[0; 4]).unwrap();
    crypto_mac.update_with_len_prefix(&[0; 8]).unwrap();
    assert_eq!(crypto_mac.finalize().unwrap(), from_base64("rgL6d_XDiBfbzevFdtktc61XB5-PkS1uQ1cj5DgfFc8").unwrap());
}

#[test]
fn pretty_fingerprint() {
    etebase::init().unwrap();

    let pubkey = from_base64(USER.pubkey).unwrap();

    let fingerprint = crypto::pretty_fingerprint(&pubkey);
    assert_eq!(fingerprint, "17756   37089   25897   42924\n06835   62184   63746   54689\n32947   01272   14138   19749\n00577   54359   44439   58177");
}
