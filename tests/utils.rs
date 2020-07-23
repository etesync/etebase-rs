// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use etebase::test_helpers::utils::{
    get_padding,
    test_buffer_pad,
    test_buffer_unpad,
};


#[test]
fn padding() {
    etebase::init().unwrap();

    // Because of how we use padding (unpadding) we need to make sure padding is always larger than the content
    // Otherwise we risk the unpadder to fail thinking it should unpad when it shouldn't.

    for i in 1..(1 << 14) {
        if get_padding(i) <= i {
            println!("Yo");
            assert_eq!(format!("Failed for {}", i), "");
        }
    }

    assert_eq!(get_padding(2343242), 2359296);
}


#[test]
fn pad_unpad() {
    etebase::init().unwrap();

    let buf = [0; 1076];
    let padded = test_buffer_pad(&buf).unwrap();
    let unpadded = test_buffer_unpad(&padded[..]).unwrap();
    assert_eq!(unpadded, &buf[..]);
}
