// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

const TEST_API_URL: &str = "http://localhost:8033";
const CLIENT_NAME: &str = "etebase-tests";

use etebase::utils::from_base64;

#[allow(dead_code)]
mod common;

use common::USER;

#[test]
fn get_login_challenge() {
    etebase::init().unwrap();

    let client = etebase::Client::new(CLIENT_NAME, TEST_API_URL, None).unwrap();
    let authenticator = etebase::online_managers::Authenticator::new(&client);

    let login_challenge = authenticator.get_login_challenge(USER.username).unwrap();
    assert_eq!(login_challenge.salt, from_base64(USER.salt).unwrap());
}
