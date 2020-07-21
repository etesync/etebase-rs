// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

const TEST_API_URL: &str = "http://localhost:8033";
const CLIENT_NAME: &str = "etebase-tests";

use etebase::utils::from_base64;

use etebase::error::Error;

#[allow(dead_code)]
mod common;

use common::{
    USER,
    USER2,
    sessionStorageKey,
};

fn user_reset(user: &common::TestUser) {
    let client = etebase::Client::new(CLIENT_NAME, TEST_API_URL).unwrap();
    let body_struct = etebase::test_helpers::SignupBody {
        user: &etebase::User {
            username: user.username,
            email: user.email,
        },
        salt: &from_base64(user.salt).unwrap(),
        pubkey: &from_base64(user.pubkey).unwrap(),
        login_pubkey: &from_base64(user.loginPubkey).unwrap(),
        encrypted_content: &from_base64(user.encryptedContent).unwrap(),
    };
    etebase::test_helpers::test_reset(&client, body_struct).unwrap();
}


#[test]
#[ignore]
fn login_and_password_change() {
    etebase::init().unwrap();
    user_reset(&USER);

    let another_password = "AnotherPassword";
    let client = etebase::Client::new(CLIENT_NAME, TEST_API_URL).unwrap();
    let mut etebase2 = etebase::Account::login(client.clone(), USER2.username, USER2.password).unwrap();

    etebase2.change_password(another_password).unwrap();

    etebase2.logout().unwrap();

    match etebase::Account::login(client.clone(), USER2.username, "BadPassword") {
        Err(Error::Http(_)) => (),
        _ => assert!(false),
    }

    // FIXME: add tests to verify that we can actually manipulate the data
    let mut etebase2 = etebase::Account::login(client.clone(), USER2.username, another_password).unwrap();

    etebase2.change_password(USER2.password).unwrap();

    etebase2.logout().unwrap();
}


#[test]
fn session_save_and_restore() {
    etebase::init().unwrap();
    user_reset(&USER);

    // FIXME: move to prepare user for test
    let client = etebase::Client::new(CLIENT_NAME, TEST_API_URL).unwrap();
    let session_key = from_base64(sessionStorageKey).unwrap();
    let etebase = etebase::Account::restore(client.clone(), USER.storedSession, Some(&session_key)).unwrap();

    // Verify we can store and restore without an encryption key
    {
        let saved = etebase.save(None).unwrap();
        let mut etebase2 = etebase::Account::restore(client.clone(), &saved, None).unwrap();

        // FIXME: we should verify we can access data instead
        &etebase2.fetch_token().unwrap();
    }

    // Verify we can store and restore with an encryption key
    {
        let key = etebase::utils::randombytes(32);
        let saved = etebase.save(Some(&key)).unwrap();
        let mut etebase2 = etebase::Account::restore(client.clone(), &saved, Some(&key)).unwrap();

        // FIXME: we should verify we can access data instead
        &etebase2.fetch_token().unwrap();
    }
}
