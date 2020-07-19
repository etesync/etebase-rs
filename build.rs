// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    match cbindgen::generate(&crate_dir) {
        Ok(gen) => gen,
        Err(e) => match e {
            // Ignore syntax errors because those will be handled later on by cargo build.
            cbindgen::Error::ParseSyntaxError {
                crate_name: _,
                src_path: _,
                error: _,
            } => return,
            _ => panic!("{:?}", e),
        },
    }.write_to_file("target/etebase.h");
}
