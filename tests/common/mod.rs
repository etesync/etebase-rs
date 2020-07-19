// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

use etebase::utils::from_base64;

pub const USER: &str = "test_user";
pub const PASSWORD: &str = "SomePassword";
pub const KEY_BASE64: &str = "Eq9b_rdbzeiU3P4sg5qN24KXbNgy8GgCeC74nFF99hI";
pub const SALT_BASE64: &str = "6y7jUaojtLq6FISBWPjwXTeiYk5cTiz1oe6HVNGvn2E";

#[allow(dead_code)]
pub fn get_encryption_key() -> Vec<u8> {
    from_base64(KEY_BASE64).unwrap()
}
