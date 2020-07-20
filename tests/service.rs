// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

const TEST_API_URL: &str = "http://localhost:8033";
const CLIENT_NAME: &str = "etebase-tests";

use etebase::utils::from_base64;

#[allow(dead_code)]
mod common;

use common::USER;

fn user_reset(user: &common::TestUser) {
    let client = etebase::Client::new(CLIENT_NAME, TEST_API_URL, None).unwrap();
    let body_struct = etebase::online_managers::SignupBody {
        user: &etebase::online_managers::User {
            username: user.username,
            email: user.email,
        },
        salt: &from_base64(user.salt).unwrap(),
        pubkey: &from_base64(user.pubkey).unwrap(),
        loginPubkey: &from_base64(user.loginPubkey).unwrap(),
        encryptedContent: &from_base64(user.encryptedContent).unwrap(),
    };
    etebase::online_managers::test_reset(&client, body_struct).unwrap();
}


#[test]
fn get_login_challenge() {
    etebase::init().unwrap();
    user_reset(&USER);

    let client = etebase::Client::new(CLIENT_NAME, TEST_API_URL, None).unwrap();
    let authenticator = etebase::online_managers::Authenticator::new(&client);

    let login_challenge = authenticator.get_login_challenge(USER.username).unwrap();
    assert_eq!(login_challenge.salt, from_base64(USER.salt).unwrap());
}
