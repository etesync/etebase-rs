// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::env;

const CLIENT_NAME: &str = "etebase-tests";

fn get_test_url() -> String {
    env::var("ETEBASE_TEST_API_URL").unwrap_or("http://localhost:8033".to_owned())
}

use etebase::utils::from_base64;

use etebase::error::Error;

macro_rules! assert_err {
    ($x:expr, $err:pat) => {
        match ($x) {
            Err($err) => (),
            _ => assert!(false),
        }
    }
}

use etebase::{
    Account,
    Client,
    Collection,
    CollectionMetadata,
    Item,
    ItemMetadata,
    FetchOptions,
};

#[allow(dead_code)]
mod common;

use common::{
    USER,
    USER2,
    TestUser,
    sessionStorageKey,
};

fn user_reset(user: &TestUser) {
    let client = Client::new(CLIENT_NAME, &get_test_url()).unwrap();
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

fn init_test(user: &TestUser) -> Account {
    etebase::init().unwrap();
    user_reset(&user);

    // FIXME: move to prepare user for test
    let client = Client::new(CLIENT_NAME, &get_test_url()).unwrap();
    let session_key = from_base64(sessionStorageKey).unwrap();

    let mut ret = Account::restore(client, user.storedSession, Some(&session_key)).unwrap();
    ret.force_api_base(&get_test_url()).unwrap();
    ret.fetch_token().unwrap();

    ret
}

fn verify_collection(col: &Collection, meta: &CollectionMetadata, content: &[u8]) {
    col.verify().unwrap();
    assert_eq!(&col.decrypt_meta().unwrap(), meta);
    assert_eq!(col.decrypt_content().unwrap(), content);
}

fn verify_item(item: &Item, meta: &ItemMetadata, content: &[u8]) {
    item.verify().unwrap();
    assert_eq!(&item.decrypt_meta().unwrap(), meta);
    assert_eq!(item.decrypt_content().unwrap(), content);
}

#[test]
fn simple_collection_handling() {
    let etebase = init_test(&USER);
    let col_mgr = etebase.get_collection_manager().unwrap();
    let meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc"));
    let content = b"SomeContent";

    let mut col = col_mgr.create(&meta, content).unwrap();
    verify_collection(&col, &meta, content);

    let meta2 = meta.clone().set_name("Collection meta2");
    col.set_meta(&meta2).unwrap();
    verify_collection(&col, &meta2, content);

    assert!(!col.is_deleted());
    col.delete().unwrap();
    assert!(col.is_deleted());
    verify_collection(&col, &meta2, content);

    etebase.logout().unwrap();
}

#[test]
fn simple_item_handling() {
    let etebase = init_test(&USER);
    let col_mgr = etebase.get_collection_manager().unwrap();
    let col_meta = CollectionMetadata::new("type", "Collection");
    let col_content = b"SomeContent";

    let col = col_mgr.create(&col_meta, col_content).unwrap();

    let it_mgr = col_mgr.get_item_manager(&col).unwrap();

    let meta = ItemMetadata::new().set_name(Some("Item 1"));
    let content = b"ItemContent";
    let mut item = it_mgr.create(&meta, content).unwrap();
    verify_item(&item, &meta, content);

    let meta2 = ItemMetadata::new().set_name(Some("Item 2"));
    item.set_meta(&meta2).unwrap();
    verify_item(&item, &meta2, content);

    assert!(!item.is_deleted());
    item.delete().unwrap();
    assert!(item.is_deleted());
    verify_item(&item, &meta2, content);

    etebase.logout().unwrap();
}

#[test]
fn simple_collection_sync() {
    let etebase = init_test(&USER);
    let col_mgr = etebase.get_collection_manager().unwrap();
    let meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc"));
    let content = b"SomeContent";

    let mut col = col_mgr.create(&meta, content).unwrap();
    verify_collection(&col, &meta, content);

    let collections = col_mgr.list(None).unwrap();
    assert_eq!(collections.data.len(), 0);

    col_mgr.upload(&col, None).unwrap();

    let collections = col_mgr.list(None).unwrap();
    assert_eq!(collections.data.len(), 1);
    verify_collection(&collections.data.first().unwrap(), &meta, content);

    let mut col_old = col_mgr.fetch(col.get_uid(), None).unwrap();
    {
        let fetch_options = FetchOptions::new().stoken(col_old.get_stoken());
        let collections = col_mgr.list(Some(&fetch_options)).unwrap();
        assert_eq!(collections.data.len(), 0);
    }

    let meta2 = meta.clone().set_name("Collection meta2");
    col.set_meta(&meta2).unwrap();

    col_mgr.upload(&col, None).unwrap();

    let collections = col_mgr.list(None).unwrap();
    assert_eq!(collections.data.len(), 1);

    {
        let fetch_options = FetchOptions::new().stoken(col_old.get_stoken());
        let collections = col_mgr.list(Some(&fetch_options)).unwrap();
        assert_eq!(collections.data.len(), 1);
    }

    // Fail uploading because of an old stoken/etag
    {
        let content2 = b"Content2";
        col_old.set_content(content2).unwrap();

        assert_err!(col_mgr.transaction(&col, None), Error::Http(_));
        let fetch_options = FetchOptions::new().stoken(col_old.get_stoken());
        assert_err!(col_mgr.upload(&col, Some(&fetch_options)), Error::Http(_));
    }

    let content2 = b"Content2";
    col.set_content(content2).unwrap();

    let collections = col_mgr.list(None).unwrap();
    assert_eq!(collections.data.len(), 1);
    verify_collection(&col, &meta2, content2);

    etebase.logout().unwrap();
}

#[test]
fn simple_item_sync() {
    let etebase = init_test(&USER);
    let col_mgr = etebase.get_collection_manager().unwrap();
    let col_meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc"));
    let col_content = b"SomeContent";

    let col = col_mgr.create(&col_meta, col_content).unwrap();

    col_mgr.upload(&col, None).unwrap();

    let it_mgr = col_mgr.get_item_manager(&col).unwrap();

    let meta = ItemMetadata::new().set_name(Some("Item 1"));
    let content = b"Content 1";

    let mut item = it_mgr.create(&meta, content).unwrap();

    it_mgr.batch(vec![&item].into_iter(), None).unwrap();

    {
        let items = it_mgr.list(None).unwrap();
        assert_eq!(items.data.len(), 1);
        verify_item(&items.data.first().unwrap(), &meta, content);
    }

    let mut item_old = it_mgr.fetch(item.get_uid(), None).unwrap();

    let meta2 = ItemMetadata::new().set_name(Some("Item 2"));
    item.set_meta(&meta2).unwrap();

    let col_old = col_mgr.fetch(col.get_uid(), None).unwrap();

    it_mgr.batch(vec![&item].into_iter(), None).unwrap();

    {
        let items = it_mgr.list(None).unwrap();
        assert_eq!(items.data.len(), 1);
        verify_item(&items.data.first().unwrap(), &meta2, content);
    }

    {
        item_old.set_content(b"Bla bla").unwrap();
        assert_err!(it_mgr.transaction(vec![&item_old].into_iter(), None), Error::Http(_));
    }

    let content2 = b"Content 2";
    item.set_content(content2).unwrap();

    {
        let fetch_options = FetchOptions::new().stoken(col_old.get_stoken());
        assert_err!(it_mgr.batch(vec![&item].into_iter(), Some(&fetch_options)), Error::Http(_));
    }

    it_mgr.transaction(vec![&item].into_iter(), None).unwrap();

    {
        let items = it_mgr.list(None).unwrap();
        assert_eq!(items.data.len(), 1);
        verify_item(&items.data.first().unwrap(), &meta2, content2);
    }

    etebase.logout().unwrap();
}

#[test]
#[ignore]
fn login_and_password_change() {
    let etebase = init_test(&USER);
    etebase.logout().unwrap();

    let another_password = "AnotherPassword";
    let client = Client::new(CLIENT_NAME, &get_test_url()).unwrap();
    let mut etebase2 = Account::login(client.clone(), USER2.username, USER2.password).unwrap();

    etebase2.change_password(another_password).unwrap();

    etebase2.logout().unwrap();

    assert_err!(Account::login(client.clone(), USER2.username, "BadPassword"), Error::Http(_));

    // FIXME: add tests to verify that we can actually manipulate the data
    let mut etebase2 = Account::login(client.clone(), USER2.username, another_password).unwrap();

    etebase2.change_password(USER2.password).unwrap();

    etebase2.logout().unwrap();
}


#[test]
fn session_save_and_restore() {
    let client = Client::new(CLIENT_NAME, &get_test_url()).unwrap();
    let etebase = init_test(&USER);

    // Verify we can store and restore without an encryption key
    {
        let saved = etebase.save(None).unwrap();
        let mut etebase2 = Account::restore(client.clone(), &saved, None).unwrap();

        // FIXME: we should verify we can access data instead
        &etebase2.fetch_token().unwrap();
    }

    // Verify we can store and restore with an encryption key
    {
        let key = etebase::utils::randombytes(32);
        let saved = etebase.save(Some(&key)).unwrap();
        let mut etebase2 = Account::restore(client.clone(), &saved, Some(&key)).unwrap();

        // FIXME: we should verify we can access data instead
        &etebase2.fetch_token().unwrap();
    }

    etebase.logout().unwrap();
}
