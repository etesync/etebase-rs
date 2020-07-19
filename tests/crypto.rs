// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use etebase::crypto;

use etebase::utils::from_base64;

mod common;

use common::{
    PASSWORD,
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
