// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::env;

use etebase::{error::Result, Account, Client, Collection, Item};

const CLIENT_NAME: &str = "etebase-example";

fn print_collection(collection: &Collection) {
    println!("UID: {}", &collection.uid());
    println!("Meta: {:?}", &collection.meta().unwrap());
    println!();
}

fn print_item(item: &Item) {
    println!("UID: {}", &item.uid());
    println!("Meta: {:?}", &item.meta().unwrap());
    println!();
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        println!("Help: ./etebase_test USERNAME PASSWORD SERVER_URL [COLLECTION_UID]");
        std::process::exit(1);
    }

    let username = &args[1];
    let password = &args[2];
    let server_url = &args[3];

    let client = Client::new(CLIENT_NAME, server_url)?;
    let etebase = Account::login(client, username, password)?;
    let col_mgr = etebase.collection_manager()?;
    if args.len() >= 5 {
        let col_uid = &args[4];
        let col = col_mgr.fetch(col_uid, None)?;
        let it_mgr = col_mgr.item_manager(&col)?;
        let items = it_mgr.list(None)?;

        print_collection(&col);
        for item in items.data() {
            print_item(&item);
        }
    } else {
        let collections = col_mgr.list("some.coltype", None)?;
        for col in collections.data() {
            print_collection(&col);
        }
    }

    etebase.logout()?;

    Ok(())
}
