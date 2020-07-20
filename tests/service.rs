// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

const TEST_API_URL: &str = "http://localhost:8033";
const CLIENT_NAME: &str = "etebase-tests";

use etebase::utils::from_base64;

#[allow(dead_code)]
mod common;

use common::USER;

fn user_reset(user: &common::TestUser) {
    let client = etebase::Client::new(CLIENT_NAME, TEST_API_URL).unwrap();
    let body_struct = etebase::test_helpers::SignupBody {
        user: &etebase::User {
            username: user.username,
            email: user.email,
        },
        salt: &from_base64(user.salt).unwrap(),
        pubkey: &from_base64(user.pubkey).unwrap(),
        loginPubkey: &from_base64(user.loginPubkey).unwrap(),
        encryptedContent: &from_base64(user.encryptedContent).unwrap(),
    };
    etebase::test_helpers::test_reset(&client, body_struct).unwrap();
}


#[test]
fn get_login_challenge() {
    etebase::init().unwrap();
    user_reset(&USER);

    let client = etebase::Client::new(CLIENT_NAME, TEST_API_URL).unwrap();
    let mut etebase = etebase::Account::login(client.clone(), USER.username, USER.password).unwrap();

    &etebase.fetch_token().unwrap();

    etebase.logout().unwrap();

    match etebase::Account::login(client.clone(), USER.username, "BadPassword") {
        Err(_e) => (),
        _ => assert!(false),
    }

    // FIXME: incomplete!!!
}
