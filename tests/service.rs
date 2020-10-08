// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::env;
use std::iter;
use std::collections::HashSet;

const CLIENT_NAME: &str = "etebase-tests";

fn test_url() -> String {
    env::var("ETEBASE_TEST_API_URL").unwrap_or("http://localhost:8033".to_owned())
}

use etebase::utils::{
    from_base64,
    randombytes_deterministic,
};

use etebase::error::{
    Result,
    Error,
};

macro_rules! assert_err {
    ($x:expr, $err:pat) => {
        match ($x) {
            Err($err) => (),
            Err(err) => None.expect(&err.to_string()),
            _ => None.expect("Got OK when expected failure"),
        }
    }
}

use etebase::{
    Account,
    Client,
    CollectionAccessLevel,
    Collection,
    CollectionMetadata,
    Item,
    ItemMetadata,
    FetchOptions,
    pretty_fingerprint,
    test_helpers::{
        test_reset,
        chunk_uids,
    }
};

#[allow(dead_code)]
mod common;

use common::{
    USER,
    USER2,
    TestUser,
    sessionStorageKey,
};

fn user_reset(user: &TestUser) -> Result<()> {
    let client = Client::new(CLIENT_NAME, &test_url())?;
    let body_struct = etebase::test_helpers::SignupBody {
        user: &etebase::User::new(user.username,user.email),
        salt: &from_base64(user.salt)?,
        pubkey: &from_base64(user.pubkey)?,
        login_pubkey: &from_base64(user.loginPubkey)?,
        encrypted_content: &from_base64(user.encryptedContent)?,
    };
    test_reset(&client, body_struct)?;

    Ok(())
}

fn init_test(user: &TestUser) -> Result<Account> {
    etebase::init()?;
    user_reset(&user)?;

    let client = Client::new(CLIENT_NAME, &test_url())?;
    let session_key = from_base64(sessionStorageKey)?;

    let mut ret = Account::restore(client, user.storedSession, Some(&session_key))?;
    ret.force_server_url(&test_url())?;
    ret.fetch_token()?;

    Ok(ret)
}

fn verify_collection(col: &Collection, meta: &CollectionMetadata, content: &[u8]) -> Result<()> {
    col.verify()?;
    assert_eq!(&col.meta()?, meta);
    assert_eq!(col.content()?, content);
    Ok(())
}

fn verify_item(item: &Item, meta: &ItemMetadata, content: &[u8]) -> Result<()> {
    item.verify()?;
    assert_eq!(&item.meta()?, meta);
    assert_eq!(item.content()?, content);
    Ok(())
}

#[test]
fn is_etebase_server() -> Result<()> {
    let client = Client::new(CLIENT_NAME, &test_url())?;
    assert!(Account::is_etebase_server(&client)?);

    let test_url = format!("{}/api/", test_url());
    let client = Client::new(CLIENT_NAME, &test_url)?;
    assert!(!Account::is_etebase_server(&client)?);

    let client = Client::new(CLIENT_NAME, "http://doesnotexist")?;
    assert!(Account::is_etebase_server(&client).is_err());

    // Verify we also fail correctly for login
    let client = Client::new(CLIENT_NAME, &test_url)?;
    assert_err!(Account::login(client.clone(), USER2.username, USER2.password), Error::NotFound(_));

    Ok(())
}

#[test]
fn get_dashboard_url() -> Result<()> {
    let etebase = init_test(&USER)?;

    match etebase.fetch_dashboard_url() {
        Ok(url) => assert!(url.len() > 0),
        err => assert_err!(err, Error::Http(_)),
    };

    etebase.logout()
}

#[test]
fn simple_collection_handling() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc")).clone();
    let content = b"SomeContent";

    let mut col = col_mgr.create(&meta, content)?;
    verify_collection(&col, &meta, content)?;

    let meta2 = meta.clone().set_name("Collection meta2").clone();
    col.set_meta(&meta2)?;
    verify_collection(&col, &meta2, content)?;

    assert!(!col.is_deleted());
    col.delete()?;
    assert!(col.is_deleted());
    verify_collection(&col, &meta2, content)?;

    etebase.logout()
}

#[test]
fn simple_item_handling() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection");
    let col_content = b"SomeContent";

    let col = col_mgr.create(&col_meta, col_content)?;

    let it_mgr = col_mgr.item_manager(&col)?;

    let meta = ItemMetadata::new().set_name(Some("Item 1")).clone();
    let content = b"ItemContent";
    let mut item = it_mgr.create(&meta, content)?;
    verify_item(&item, &meta, content)?;

    let meta2 = ItemMetadata::new().set_name(Some("Item 2")).clone();
    item.set_meta(&meta2)?;
    verify_item(&item, &meta2, content)?;

    assert!(!item.is_deleted());
    item.delete()?;
    assert!(item.is_deleted());
    verify_item(&item, &meta2, content)?;

    etebase.logout()
}

#[test]
fn simple_collection_sync() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc")).clone();
    let content = b"SomeContent";

    let mut col = col_mgr.create(&meta, content)?;
    verify_collection(&col, &meta, content)?;

    let collections = col_mgr.list(None)?;
    assert_eq!(collections.data().len(), 0);

    col_mgr.upload(&col, None)?;

    let collections = col_mgr.list(None)?;
    assert_eq!(collections.data().len(), 1);
    verify_collection(&collections.data().first().unwrap(), &meta, content)?;

    let mut col_old = col_mgr.fetch(col.uid(), None)?;
    {
        let fetch_options = FetchOptions::new().stoken(col_old.stoken());
        let collections = col_mgr.list(Some(&fetch_options))?;
        assert_eq!(collections.data().len(), 0);
    }

    let meta2 = meta.clone().set_name("Collection meta2").clone();
    col.set_meta(&meta2)?;

    col_mgr.upload(&col, None)?;

    let collections = col_mgr.list(None)?;
    assert_eq!(collections.data().len(), 1);

    {
        let fetch_options = FetchOptions::new().stoken(col_old.stoken());
        let collections = col_mgr.list(Some(&fetch_options))?;
        assert_eq!(collections.data().len(), 1);
    }

    // Fail uploading because of an old stoken/etag
    {
        let content2 = b"Content2";
        col_old.set_content(content2)?;

        assert_err!(col_mgr.transaction(&col, None), Error::Conflict(_));
        let fetch_options = FetchOptions::new().stoken(col_old.stoken());
        assert_err!(col_mgr.upload(&col, Some(&fetch_options)), Error::Conflict(_));
    }

    let content2 = b"Content2";
    col.set_content(content2)?;

    let collections = col_mgr.list(None)?;
    assert_eq!(collections.data().len(), 1);
    verify_collection(&col, &meta2, content2)?;

    etebase.logout()
}

#[test]
fn simple_item_sync() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc")).clone();
    let col_content = b"SomeContent";

    let col = col_mgr.create(&col_meta, col_content)?;

    col_mgr.upload(&col, None)?;

    let it_mgr = col_mgr.item_manager(&col)?;

    let meta = ItemMetadata::new().set_name(Some("Item 1")).clone();
    let content = b"Content 1";

    let mut item = it_mgr.create(&meta, content)?;

    it_mgr.batch(iter::once(&item), None)?;

    {
        let items = it_mgr.list(None)?;
        assert_eq!(items.data().len(), 1);
        verify_item(&items.data().first().unwrap(), &meta, content)?;
    }

    let mut item_old = it_mgr.fetch(item.uid(), None)?;

    let meta2 = ItemMetadata::new().set_name(Some("Item 2")).clone();
    item.set_meta(&meta2)?;

    let col_old = col_mgr.fetch(col.uid(), None)?;

    it_mgr.batch(iter::once(&item), None)?;

    {
        let items = it_mgr.list(None)?;
        assert_eq!(items.data().len(), 1);
        verify_item(&items.data().first().unwrap(), &meta2, content)?;
    }

    {
        item_old.set_content(b"Bla bla")?;
        assert_err!(it_mgr.transaction(iter::once(&item_old), None), Error::Conflict(_));
    }

    let content2 = b"Content 2";
    item.set_content(content2)?;

    {
        let fetch_options = FetchOptions::new().stoken(col_old.stoken());
        assert_err!(it_mgr.batch(iter::once(&item), Some(&fetch_options)), Error::Conflict(_));
    }

    it_mgr.transaction(iter::once(&item), None)?;

    {
        let items = it_mgr.list(None)?;
        assert_eq!(items.data().len(), 1);
        verify_item(&items.data().first().unwrap(), &meta2, content2)?;
    }

    etebase.logout()
}

#[test]
fn collection_as_item() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc")).clone();
    let col_content = b"SomeContent";

    let mut col = col_mgr.create(&col_meta, col_content)?;

    col_mgr.upload(&col, None)?;

    let it_mgr = col_mgr.item_manager(&col)?;

    // Verify with_collection works
    {
        let items = it_mgr.list(None)?;
        assert_eq!(items.data().len(), 0);
        let fetch_options = FetchOptions::new().with_collection(true);
        let items = it_mgr.list(Some(&fetch_options))?;
        assert_eq!(items.data().len(), 1);
        let meta = col.item()?.meta()?;
        let first_item = items.data().first().unwrap();
        verify_item(&first_item, &meta, col_content)?;
        // Also verify the collection metadata is good
        assert_eq!(&first_item.meta_generic::<CollectionMetadata>()?, &col_meta);
    }

    let meta = ItemMetadata::new().clone();
    let content = b"Item data";
    let item = it_mgr.create(&meta, content)?;

    it_mgr.batch(iter::once(&item), None)?;

    {
        let items = it_mgr.list(None)?;
        assert_eq!(items.data().len(), 1);
        let fetch_options = FetchOptions::new().with_collection(true);
        let items = it_mgr.list(Some(&fetch_options))?;
        assert_eq!(items.data().len(), 2);
    }

    let col_item_old = it_mgr.fetch(col.uid(), None)?;

    // Manipulate the collection with batch/transaction
    let col_content2 = b"Other content";
    col.set_content(col_content2)?;
    it_mgr.batch([col.item()?].iter(), None)?;

    {
        let collections = col_mgr.list(None)?;
        assert_eq!(collections.data().len(), 1);
        verify_collection(&collections.data().first().unwrap(), &col_meta, col_content2)?;
    }

    let mut col = col_mgr.fetch(col.uid(), None)?;
    let col_content2 = b"Other content 3";
    col.set_content(col_content2)?;
    it_mgr.transaction([col.item()?].iter(), None)?;

    {
        let collections = col_mgr.list(None)?;
        assert_eq!(collections.data().len(), 1);
        verify_collection(&collections.data().first().unwrap(), &col_meta, col_content2)?;
    }

    {
        let updates = it_mgr.fetch_updates(vec![&col_item_old, &item].into_iter(), None)?;
        assert_eq!(updates.data().len(), 1);
        let meta = col.item()?.meta()?;
        let first_item = updates.data().first().unwrap();
        verify_item(&first_item, &meta, col_content2)?;
        // Also verify the collection metadata is good
        assert_eq!(&first_item.meta_generic::<CollectionMetadata>()?, &col_meta);
    }

    etebase.logout()
}

#[test]
fn collection_and_item_deletion() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection");
    let col_content = b"";

    let mut col = col_mgr.create(&col_meta, col_content)?;

    col_mgr.upload(&col, None)?;

    let it_mgr = col_mgr.item_manager(&col)?;

    let meta = ItemMetadata::new().set_name(Some("Item 1")).clone();
    let content = b"Content 1";

    let mut item = it_mgr.create(&meta, content)?;

    it_mgr.batch(iter::once(&item), None)?;

    let items = it_mgr.list(None)?;
    assert_eq!(items.data().len(), 1);

    item.delete()?;
    it_mgr.batch(iter::once(&item), None)?;

    {
        let fetch_options = FetchOptions::new().stoken(items.stoken());
        let items = it_mgr.list(Some(&fetch_options))?;
        assert_eq!(items.data().len(), 1);
        let first_item = items.data().first().unwrap();
        verify_item(&first_item, &meta, content)?;
        assert!(first_item.is_deleted());
    }

    col.delete()?;
    col_mgr.upload(&col, None)?;

    {
        let fetch_options = FetchOptions::new().stoken(col.stoken());
        let collections = col_mgr.list(Some(&fetch_options))?;
        assert_eq!(collections.data().len(), 1);

        let first_col = collections.data().first().unwrap();
        verify_collection(&first_col, &col_meta, col_content)?;
        assert!(first_col.is_deleted());
    }

    etebase.logout()
}

#[test]
fn empty_content() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection");
    let col_content = b"";

    let col = col_mgr.create(&col_meta, col_content)?;

    col_mgr.upload(&col, None)?;

    {
        let col2 = col_mgr.fetch(col.uid(), None)?;
        verify_collection(&col2, &col_meta, col_content)?;
    }

    let it_mgr = col_mgr.item_manager(&col)?;

    let meta = ItemMetadata::new().set_name(Some("Item 1")).clone();
    let content = b"";

    let item = it_mgr.create(&meta, content)?;

    it_mgr.transaction(iter::once(&item), None)?;

    {
        let items = it_mgr.list(None)?;
        let first_item = items.data().first().unwrap();
        verify_item(&first_item, &meta, content)?;
    }

    etebase.logout()
}

#[test]
fn list_response_correctness() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection");
    let col_content = b"";

    let col = col_mgr.create(&col_meta, col_content)?;

    col_mgr.upload(&col, None)?;

    {
        let col2 = col_mgr.fetch(col.uid(), None)?;
        verify_collection(&col2, &col_meta, col_content)?;
    }

    let it_mgr = col_mgr.item_manager(&col)?;

    let items: Vec<Item> = (0..5).into_iter()
        .map(|i| {
            let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i))).clone();
            let content = b"";
            it_mgr.create(&meta, content).unwrap()
        })
        .collect();

    it_mgr.batch(items.iter(), None)?;

    {
        let items = it_mgr.list(None)?;
        assert_eq!(items.data().len(), 5);
        assert!(items.done());
        let fetch_options = FetchOptions::new().limit(5);
        let items = it_mgr.list(Some(&fetch_options))?;
        assert!(items.done());
    }

    let mut stoken = None;
    for i in 0..3 {
        let fetch_options = FetchOptions::new().limit(2).stoken(stoken.as_deref());
        let items = it_mgr.list(Some(&fetch_options))?;
        assert_eq!(items.done(), i == 2);
        stoken = items.stoken().map(str::to_string);
    }

    // Also check collections
    for i in 0..4 {
        let meta = CollectionMetadata::new("col", &format!("Item {}", i));
        let content = b"";
        let col = col_mgr.create(&meta, content).unwrap();
        col_mgr.upload(&col, None)?;
    }

    {
        let collections = col_mgr.list(None)?;
        assert_eq!(collections.data().len(), 5);
        assert!(collections.done());
        let fetch_options = FetchOptions::new().limit(5);
        let collections = col_mgr.list(Some(&fetch_options))?;
        assert!(collections.done());
        assert!(collections.done());
    }

    let mut stoken = None;
    for i in 0..3 {
        let fetch_options = FetchOptions::new().limit(2).stoken(stoken.as_deref());
        let collections = col_mgr.list(Some(&fetch_options))?;
        assert_eq!(collections.done(), i == 2);
        stoken = collections.stoken().map(str::to_string);
    }

    etebase.logout()
}

#[test]
fn item_transactions() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection");
    let col_content = b"";

    let col = col_mgr.create(&col_meta, col_content)?;

    col_mgr.upload(&col, None)?;

    let it_mgr = col_mgr.item_manager(&col)?;
    let meta = ItemMetadata::new().set_name(Some("Item 1")).clone();
    let content = b"";
    let mut item = it_mgr.create(&meta, content)?;

    let deps = vec![&item];
    it_mgr.transaction(deps.clone().into_iter(), None)?;

    let item_old = it_mgr.fetch(item.uid(), None)?;
    let mut item_old2 = it_mgr.fetch(item.uid(), None)?;

    let items: Vec<Item> = (0..5).into_iter()
        .map(|i| {
            let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i))).clone();
            let content = b"";
            it_mgr.create(&meta, content).unwrap()
        })
        .collect();

    it_mgr.transaction_deps(items.iter(), deps.clone().into_iter(), None)?;

    {
        let items = it_mgr.list(None)?;
        assert_eq!(items.data().len(), 6);
    }

    let meta2 = ItemMetadata::new().set_name(Some("some")).clone();
    item.set_meta(&meta2)?;
    let deps = vec![&item];

    it_mgr.transaction_deps(iter::once(&item), deps.clone().into_iter(), None)?;

    {
        let items = it_mgr.list(None)?;
        assert_eq!(items.data().len(), 6);
    }

    {
        let meta3 = ItemMetadata::new().set_name(Some("some2")).clone();
        item.set_meta(&meta3)?;

        let deps2 = items.iter().chain(iter::once(&item_old));

        // Old in the deps
        assert_err!(it_mgr.transaction_deps(iter::once(&item), deps2.into_iter(), None), Error::Conflict(_));
        it_mgr.transaction(iter::once(&item), None)?;

        item_old2.set_meta(&meta3)?;

        // Old stoken in the item itself
        assert_err!(it_mgr.transaction(iter::once(&item_old2), None), Error::Conflict(_));
    }

    {
        let meta3 = ItemMetadata::new().set_name(Some("some3")).clone();
        let mut item2 = it_mgr.fetch(items[0].uid(), None)?;
        item2.set_meta(&meta3)?;

        item_old2.set_meta(&meta3)?;

        // Part of the transaction is bad, and part is good
        assert_err!(it_mgr.transaction(vec![&item2, &item_old2].into_iter(), None), Error::Conflict(_));

        // Verify it hasn't changed after the transaction above failed
        let item2_fetch = it_mgr.fetch(item2.uid(), None)?;
        assert_ne!(item2_fetch.meta()?, item2.meta()?);
    }

    {
        // Global stoken test
        let meta3 = ItemMetadata::new().set_name(Some("some4")).clone();
        item.set_meta(&meta3)?;

        let new_col = col_mgr.fetch(col.uid(), None)?;
        let stoken = new_col.stoken();
        let bad_etag = col.etag();

        let fetch_options = FetchOptions::new().stoken(Some(bad_etag));
        assert_err!(it_mgr.transaction(iter::once(&item), Some(&fetch_options)), Error::Conflict(_));

        let fetch_options = FetchOptions::new().stoken(stoken);
        it_mgr.transaction(iter::once(&item), Some(&fetch_options))?;
    }

    etebase.logout()
}

#[test]
fn item_batch_stoken() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection");
    let col_content = b"";

    let col = col_mgr.create(&col_meta, col_content)?;

    col_mgr.upload(&col, None)?;

    let it_mgr = col_mgr.item_manager(&col)?;
    let meta = ItemMetadata::new().set_name(Some("Item Orig")).clone();
    let content = b"";
    let mut item = it_mgr.create(&meta, content)?;

    it_mgr.batch(iter::once(&item), None)?;

    let mut item2 = it_mgr.fetch(item.uid(), None)?;

    let items: Vec<Item> = (0..5).into_iter()
        .map(|i| {
            let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i))).clone();
            let content = b"";
            it_mgr.create(&meta, content).unwrap()
        })
        .collect();

    it_mgr.batch(items.iter(), None)?;

    {
        let meta3 = ItemMetadata::new().set_name(Some("some2")).clone();
        item2.set_meta(&meta3)?;
        it_mgr.batch(iter::once(&item2), None)?;

        let meta3 = ItemMetadata::new().set_name(Some("some3")).clone();
        item.set_meta(&meta3)?;

        // Old stoken in the item itself should work for batch and fail for transaction or batch with deps
        assert_err!(it_mgr.transaction(iter::once(&item), None), Error::Conflict(_));
        assert_err!(it_mgr.batch_deps(iter::once(&item), iter::once(&item), None), Error::Conflict(_));

        it_mgr.batch(iter::once(&item), None)?;
    }

    {
        // Global stoken test
        let meta3 = ItemMetadata::new().set_name(Some("some4")).clone();
        item.set_meta(&meta3)?;

        let new_col = col_mgr.fetch(col.uid(), None)?;
        let stoken = new_col.stoken();
        let bad_etag = col.etag();

        let fetch_options = FetchOptions::new().stoken(Some(bad_etag));
        assert_err!(it_mgr.batch(iter::once(&item), Some(&fetch_options)), Error::Conflict(_));

        let fetch_options = FetchOptions::new().stoken(stoken);
        it_mgr.batch(iter::once(&item), Some(&fetch_options))?;
    }

    etebase.logout()
}

#[test]
fn item_fetch_updates() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection");
    let col_content = b"";

    let col = col_mgr.create(&col_meta, col_content)?;

    col_mgr.upload(&col, None)?;

    let it_mgr = col_mgr.item_manager(&col)?;
    let meta = ItemMetadata::new().set_name(Some("Item Orig")).clone();
    let content = b"";
    let item = it_mgr.create(&meta, content)?;

    it_mgr.batch(iter::once(&item), None)?;

    let items: Vec<Item> = (0..5).into_iter()
        .map(|i| {
            let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i))).clone();
            let content = b"";
            it_mgr.create(&meta, content).unwrap()
        })
        .collect();

    it_mgr.batch(items.iter(), None)?;

    {
        let items = it_mgr.list(None)?;
        assert_eq!(items.data().len(), 6);
    }

    let new_col = col_mgr.fetch(col.uid(), None)?;
    let stoken = new_col.stoken();

    {
        let updates = it_mgr.fetch_updates(items.iter(), None)?;
        assert_eq!(updates.data().len(), 0);

        let fetch_options = FetchOptions::new().stoken(stoken);
        let updates = it_mgr.fetch_updates(items.iter(), Some(&fetch_options))?;
        assert_eq!(updates.data().len(), 0);
    }

    {
        let mut item2 = it_mgr.fetch(items[0].uid(), None)?;
        let meta3 = ItemMetadata::new().set_name(Some("some2")).clone();
        item2.set_meta(&meta3)?;
        it_mgr.batch(iter::once(&item2), None)?;
    }

    {
        let updates = it_mgr.fetch_updates(items.iter(), None)?;
        assert_eq!(updates.data().len(), 1);

        let fetch_options = FetchOptions::new().stoken(stoken);
        let updates = it_mgr.fetch_updates(items.iter(), Some(&fetch_options))?;
        assert_eq!(updates.data().len(), 1);
    }

    {
        let item2 = it_mgr.fetch(items[0].uid(), None)?;
        let updates = it_mgr.fetch_updates(iter::once(&item2), None)?;
        assert_eq!(updates.data().len(), 0);

        let fetch_options = FetchOptions::new().stoken(stoken);
        let updates = it_mgr.fetch_updates(iter::once(&item2), Some(&fetch_options))?;
        assert_eq!(updates.data().len(), 1);
    }

    let new_col = col_mgr.fetch(col.uid(), None)?;
    let stoken = new_col.stoken();

    {
        let fetch_options = FetchOptions::new().stoken(stoken);
        let updates = it_mgr.fetch_updates(items.iter(), Some(&fetch_options))?;
        assert_eq!(updates.data().len(), 0);
    }

    etebase.logout()
}

#[test]
fn item_revisions() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection");
    let col_content = b"";

    let col = col_mgr.create(&col_meta, col_content)?;

    col_mgr.upload(&col, None)?;

    let it_mgr = col_mgr.item_manager(&col)?;
    let meta = ItemMetadata::new().set_name(Some("Item Orig")).clone();
    let content = b"";
    let mut item = it_mgr.create(&meta, content)?;

    for i in 0..5 {
        let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i))).clone();
        item.set_meta(&meta)?;
        it_mgr.batch(iter::once(&item), None)?;
    }

    {
        let meta = ItemMetadata::new().set_name(Some("Latest")).clone();
        item.set_meta(&meta)?;
        it_mgr.batch(iter::once(&item), None)?;
    }

    {
        let etag = item.etag();
        let fetch_options = FetchOptions::new().iterator(Some(etag));
        let revisions = it_mgr.item_revisions(&item, Some(&fetch_options))?;
        assert_eq!(revisions.data().len(), 5);
        assert!(revisions.done());

        let etag = item.etag();
        let fetch_options = FetchOptions::new().iterator(Some(etag)).limit(5);
        let revisions = it_mgr.item_revisions(&item, Some(&fetch_options))?;
        assert_eq!(revisions.data().len(), 5);
        assert!(revisions.done());

        for i in 0..5 {
            let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i))).clone();
            let rev = &revisions.data()[4 - i];
            assert_eq!(&rev.meta()?, &meta);
        }

        // Iterate through revisions
        {
            let mut iterator = None;
            for i in 0..2 {
                let fetch_options = FetchOptions::new().limit(2).stoken(iterator.as_deref());
                let revisions = it_mgr.item_revisions(&item, Some(&fetch_options))?;
                assert_eq!(revisions.done(), i == 2);
                iterator = revisions.iterator().map(str::to_string);
            }
        }
    }

    etebase.logout()
}

#[test]
fn collection_invitations() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection");
    let col_content = b"";

    let col = col_mgr.create(&col_meta, col_content)?;

    col_mgr.upload(&col, None)?;

    let it_mgr = col_mgr.item_manager(&col)?;

    let items: Vec<Item> = (0..5).into_iter()
        .map(|i| {
            let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i))).clone();
            let content = b"";
            it_mgr.create(&meta, content).unwrap()
        })
        .collect();

    it_mgr.batch(items.iter(), None)?;

    let invite_mgr = etebase.invitation_manager()?;

    let etebase2 = init_test(&USER2)?;
    let col_mgr2 = etebase2.collection_manager()?;
    let invite_mgr2 = etebase2.invitation_manager()?;

    let user2_profile = invite_mgr.fetch_user_profile(USER2.username)?;
    // Should be verified by user1 off-band
    let user2_pubkey = invite_mgr2.pubkey();
    assert_eq!(&user2_profile.pubkey(), &user2_pubkey);
    // Off-band verification:
    assert_eq!(pretty_fingerprint(&user2_profile.pubkey()), pretty_fingerprint(user2_pubkey));

    invite_mgr.invite(&col, USER2.username, &user2_profile.pubkey(), CollectionAccessLevel::ReadWrite)?;

    let invitations = invite_mgr.list_outgoing(None)?;
    assert_eq!(invitations.data().len(), 1);

    let invitations = invite_mgr2.list_incoming(None)?;
    assert_eq!(invitations.data().len(), 1);
    {
        let invitation = invitations.data().first().unwrap();
        assert_eq!(invitation.from_username().unwrap(), USER.username);
    }

    invite_mgr2.reject(invitations.data().first().unwrap())?;

    {
        let collections = col_mgr2.list(None)?;
        assert_eq!(collections.data().len(), 0);
        let invitations = invite_mgr2.list_incoming(None)?;
        assert_eq!(invitations.data().len(), 0);
    }

    // Invite and then disinvite
    invite_mgr.invite(&col, USER2.username, &user2_profile.pubkey(), CollectionAccessLevel::ReadWrite)?;

    let invitations = invite_mgr2.list_incoming(None)?;
    assert_eq!(invitations.data().len(), 1);

    invite_mgr.disinvite(invitations.data().first().unwrap())?;

    {
        let collections = col_mgr2.list(None)?;
        assert_eq!(collections.data().len(), 0);
        let invitations = invite_mgr2.list_incoming(None)?;
        assert_eq!(invitations.data().len(), 0);
    }

    // Invite again, this time accept
    invite_mgr.invite(&col, USER2.username, &user2_profile.pubkey(), CollectionAccessLevel::ReadWrite)?;

    let invitations = invite_mgr2.list_incoming(None)?;
    assert_eq!(invitations.data().len(), 1);

    let stoken = col_mgr.fetch(col.uid(), None)?.stoken().map(str::to_string);

    // Should be verified by user2 off-band
    let user1_pubkey = invite_mgr.pubkey();
    let invitation = invitations.data().first().unwrap();
    assert_eq!(invitation.from_pubkey(), user1_pubkey);

    invite_mgr2.accept(invitation)?;

    {
        let collections = col_mgr2.list(None)?;
        assert_eq!(collections.data().len(), 1);
        // Verify we can decrypt it and it's what we expect
        let col2 = collections.data().first().unwrap();
        verify_collection(col2, &col_meta, col_content)?;

        let invitations = invite_mgr2.list_incoming(None)?;
        assert_eq!(invitations.data().len(), 0);
    }

    let col2 = col_mgr2.fetch(col.uid(), None)?;
    let member_mgr2 = col_mgr2.member_manager(&col2)?;

    member_mgr2.leave()?;

    {
        let fetch_options = FetchOptions::new().stoken(stoken.as_deref());
        let collections = col_mgr2.list(Some(&fetch_options))?;
        assert_eq!(collections.data().len(), 0);
        assert_eq!(collections.removed_memberships().unwrap().len(), 1);
    }

    // Add again
    invite_mgr.invite(&col, USER2.username, &user2_profile.pubkey(), CollectionAccessLevel::ReadWrite)?;

    let invitations = invite_mgr2.list_incoming(None)?;
    assert_eq!(invitations.data().len(), 1);
    let invitation = invitations.data().first().unwrap();
    invite_mgr2.accept(invitation)?;

    {
        let new_col = col_mgr.fetch(col.uid(), None)?;
        assert_ne!(stoken.as_deref(), new_col.stoken());

        let fetch_options = FetchOptions::new().stoken(stoken.as_deref());
        let collections = col_mgr2.list(Some(&fetch_options))?;
        assert_eq!(collections.data().len(), 1);
        let first_col = collections.data().first().unwrap();
        assert_eq!(first_col.uid(), col.uid());
        assert!(collections.removed_memberships().is_none());
    }

    // Remove
    {
        let new_col = col_mgr.fetch(col.uid(), None)?;
        assert_ne!(stoken.as_deref(), new_col.stoken());

        let member_mgr = col_mgr.member_manager(&col)?;
        member_mgr.remove(USER2.username)?;

        let fetch_options = FetchOptions::new().stoken(stoken.as_deref());
        let collections = col_mgr2.list(Some(&fetch_options))?;
        assert_eq!(collections.data().len(), 0);
        assert_eq!(collections.removed_memberships().unwrap().len(), 1);

        let stoken = new_col.stoken();

        let fetch_options = FetchOptions::new().stoken(stoken.as_deref());
        let collections = col_mgr2.list(Some(&fetch_options))?;
        assert_eq!(collections.data().len(), 0);
        assert_eq!(collections.removed_memberships().unwrap().len(), 1);
    }

    etebase2.logout()?;
    etebase.logout()
}

#[test]
fn iterating_invitations() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;

    let etebase2 = init_test(&USER2)?;
    let invite_mgr2 = etebase2.invitation_manager()?;

    let invite_mgr = etebase.invitation_manager()?;
    let user2_profile = invite_mgr.fetch_user_profile(USER2.username)?;

    for i in 0..3 {
        let meta = CollectionMetadata::new("col", &format!("Item {}", i));
        let content = b"";
        let col = col_mgr.create(&meta, content).unwrap();
        col_mgr.upload(&col, None)?;
        invite_mgr.invite(&col, USER2.username, &user2_profile.pubkey(), CollectionAccessLevel::ReadWrite)?;
    }

    // Check incoming
    let invitations = invite_mgr2.list_incoming(None)?;
    assert_eq!(invitations.data().len(), 3);

    {
        let mut iterator = None;
        for i in 0..2 {
            let fetch_options = FetchOptions::new().limit(2).iterator(iterator.as_deref());
            let invitations = invite_mgr2.list_incoming(Some(&fetch_options))?;
            assert_eq!(invitations.done(), i == 1);
            iterator = invitations.iterator().map(str::to_string);
        }
    }

    // Check outgoing
    let invitations = invite_mgr.list_outgoing(None)?;
    assert_eq!(invitations.data().len(), 3);

    {
        let mut iterator = None;
        for i in 0..2 {
            let fetch_options = FetchOptions::new().limit(2).iterator(iterator.as_deref());
            let invitations = invite_mgr.list_outgoing(Some(&fetch_options))?;
            assert_eq!(invitations.done(), i == 1);
            iterator = invitations.iterator().map(str::to_string);
        }
    }

    etebase2.logout()?;
    etebase.logout()
}

#[test]
fn collection_access_level() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection");
    let col_content = b"";

    let col = col_mgr.create(&col_meta, col_content)?;
    col_mgr.upload(&col, None)?;

    let it_mgr = col_mgr.item_manager(&col)?;

    let items: Vec<Item> = (0..5).into_iter()
        .map(|i| {
            let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i))).clone();
            let content = b"";
            it_mgr.create(&meta, content).unwrap()
        })
        .collect();

    it_mgr.batch(items.iter(), None)?;

    let etebase2 = init_test(&USER2)?;
    let col_mgr2 = etebase2.collection_manager()?;
    let invite_mgr2 = etebase2.invitation_manager()?;

    let invite_mgr = etebase.invitation_manager()?;
    let member_mgr = col_mgr.member_manager(&col)?;
    let user2_profile = invite_mgr.fetch_user_profile(USER2.username)?;

    invite_mgr.invite(&col, USER2.username, &user2_profile.pubkey(), CollectionAccessLevel::ReadWrite)?;

    let invitations = invite_mgr2.list_incoming(None)?;
    invite_mgr2.accept(invitations.data().first().unwrap())?;

    let col2 = col_mgr2.fetch(col.uid(), None)?;
    assert_eq!(col2.access_level(), CollectionAccessLevel::ReadWrite);

    let it_mgr2 = col_mgr2.item_manager(&col2)?;

    // Item creation: success
    {
        let members = member_mgr.list(None)?;
        assert_eq!(members.data().len(), 2);
        for member in members.data() {
            if member.username() == USER2.username {
                assert_eq!(member.access_level(), CollectionAccessLevel::ReadWrite);
            }
        }

        let meta = ItemMetadata::new().set_name(Some("Some item")).clone();
        let content = b"";
        let item = it_mgr2.create(&meta, content)?;
        it_mgr2.batch(iter::once(&item), None)?;
    }

    member_mgr.modify_access_level(USER2.username, CollectionAccessLevel::ReadOnly)?;

    let col2 = col_mgr2.fetch(col.uid(), None)?;
    assert_eq!(col2.access_level(), CollectionAccessLevel::ReadOnly);

    // Item creation: fail
    {
        let members = member_mgr.list(None)?;
        assert_eq!(members.data().len(), 2);
        for member in members.data() {
            if member.username() == USER2.username {
                assert_eq!(member.access_level(), CollectionAccessLevel::ReadOnly);
            }
        }

        let meta = ItemMetadata::new().set_name(Some("Some item")).clone();
        let content = b"";
        let item = it_mgr2.create(&meta, content)?;
        assert_err!(it_mgr2.batch(iter::once(&item), None), Error::PermissionDenied(_));
    }

    member_mgr.modify_access_level(USER2.username, CollectionAccessLevel::Admin)?;

    // Item creation: success
    {
        let members = member_mgr.list(None)?;
        assert_eq!(members.data().len(), 2);
        for member in members.data() {
            if member.username() == USER2.username {
                assert_eq!(member.access_level(), CollectionAccessLevel::Admin);
            }
        }

        let meta = ItemMetadata::new().set_name(Some("Some item")).clone();
        let content = b"";
        let item = it_mgr2.create(&meta, content)?;
        it_mgr2.batch(iter::once(&item), None)?;
    }

    // Iterate members
    {
        let fetch_options = FetchOptions::new().limit(1);
        let members = member_mgr.list(Some(&fetch_options))?;
        assert_eq!(members.data().len(), 1);
        let fetch_options = FetchOptions::new().limit(1).iterator(members.iterator());
        let members2 = member_mgr.list(Some(&fetch_options))?;
        assert_eq!(members2.data().len(), 1);
        assert!(members2.done());
        // Verify we got two different usersnames
        assert_ne!(members.data().first().unwrap().username(), members2.data().first().unwrap().username());

        let members = member_mgr.list(None)?;
        assert!(members.done());
    }

    etebase2.logout()?;
    etebase.logout()
}

#[test]
fn chunking_large_data() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc")).clone();
    let col_content = b"SomeContent";

    let col = col_mgr.create(&col_meta, col_content)?;

    col_mgr.upload(&col, None)?;

    let it_mgr = col_mgr.item_manager(&col)?;

    let meta = ItemMetadata::new().clone();
    let content = randombytes_deterministic(120 * 1024, &[0; 32]); // 120kb of pseuedorandom data

    let mut item = it_mgr.create(&meta, &content)?;
    verify_item(&item, &meta, &content)?;

    let mut uid_set = HashSet::new();

    // Get the first chunks and init uid_set
    {
        let chunks = chunk_uids(&item);
        assert_eq!(chunks.len(), 8);
        for chunk in chunks {
            uid_set.insert(chunk);
        }
    }

    // Bite a chunk off the new buffer
    let bite_start = 10000_usize;
    let bite_size = 210_usize;
    let mut new_buf = [&content[..bite_start], &content[bite_start + bite_size..]].concat();

    new_buf[39000] = 0;
    new_buf[39001] = 1;
    new_buf[39002] = 2;
    new_buf[39003] = 3;
    new_buf[39004] = 4;

    item.set_content(&new_buf)?;
    verify_item(&item, &meta, &new_buf)?;

    // Verify how much has changed
    {
        let chunks = chunk_uids(&item);
        assert_eq!(chunks.len(), 8);

        let mut reused = 0;
        for chunk in chunks {
            if uid_set.contains(&chunk) {
                reused += 1;
            }
        }

        assert_eq!(reused, 5);
    }

    etebase.logout()
}

#[test]
#[ignore]
fn login_and_password_change() -> Result<()> {
    // Reset both users
    let etebase = init_test(&USER)?;
    etebase.logout()?;
    let etebase2 = init_test(&USER2)?;
    etebase2.logout()?;

    let another_password = "AnotherPassword";
    let client = Client::new(CLIENT_NAME, &test_url())?;
    let mut etebase2 = Account::login(client.clone(), USER2.username, USER2.password)?;

    let col_mgr2 = etebase2.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc")).clone();
    let col_content = b"SomeContent";

    let col = col_mgr2.create(&col_meta, col_content)?;
    col_mgr2.upload(&col, None)?;

    etebase2.change_password(another_password)?;

    {
        // Verify we can still access the data
        let collections = col_mgr2.list(None)?;
        verify_collection(collections.data().first().unwrap(), &col_meta, col_content)?;
    }

    etebase2.logout()?;

    assert_err!(Account::login(client.clone(), USER2.username, "BadPassword"), Error::Unauthorized(_));

    let mut etebase2 = Account::login(client.clone(), USER2.username, another_password)?;

    let col_mgr2 = etebase2.collection_manager()?;

    {
        // Verify we can still access the data
        let collections = col_mgr2.list(None)?;
        verify_collection(collections.data().first().unwrap(), &col_meta, col_content)?;
    }

    etebase2.change_password(USER2.password)?;

    etebase2.logout()
}


#[test]
fn session_save_and_restore() -> Result<()> {
    let client = Client::new(CLIENT_NAME, &test_url())?;
    let etebase = init_test(&USER)?;

    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc")).clone();
    let col_content = b"SomeContent";

    let col = col_mgr.create(&col_meta, col_content)?;
    col_mgr.upload(&col, None)?;

    // Verify we can store and restore without an encryption key
    {
        let saved = etebase.save(None)?;
        let etebase2 = Account::restore(client.clone(), &saved, None)?;

        let col_mgr2 = etebase2.collection_manager()?;
        let collections = col_mgr2.list(None)?;
        verify_collection(collections.data().first().unwrap(), &col_meta, col_content)?;
    }

    // Verify we can store and restore with an encryption key
    {
        let key = etebase::utils::randombytes(32);
        let saved = etebase.save(Some(&key))?;
        assert_err!(Account::restore(client.clone(), &saved, None), Error::Encryption(_));
        let etebase2 = Account::restore(client.clone(), &saved, Some(&key))?;

        let col_mgr2 = etebase2.collection_manager()?;
        let collections = col_mgr2.list(None)?;
        verify_collection(collections.data().first().unwrap(), &col_meta, col_content)?;
    }

    etebase.logout()
}

#[test]
fn cache_collections_and_items() -> Result<()> {
    let etebase = init_test(&USER)?;

    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc")).clone();
    let col_content = b"SomeContent";

    let col = col_mgr.create(&col_meta, col_content)?;
    col_mgr.upload(&col, None)?;

    let it_mgr = col_mgr.item_manager(&col)?;

    let meta = ItemMetadata::new().set_name(Some("Item")).clone();
    let content = b"SomeItemContent";
    let item = it_mgr.create(&meta, content)?;

    it_mgr.batch(iter::once(&item), None)?;

    // With content
    {
        let saved_col = col_mgr.cache_save_with_content(&col)?;
        let loaded_col = col_mgr.cache_load(&saved_col)?;
        assert_eq!(col.uid(), loaded_col.uid());
        assert_eq!(col.etag(), loaded_col.etag());
        verify_collection(&loaded_col, &col_meta, col_content)?;

        let saved_item = it_mgr.cache_save_with_content(&item)?;
        let loaded_item = it_mgr.cache_load(&saved_item)?;
        assert_eq!(item.uid(), loaded_item.uid());
        assert_eq!(item.etag(), loaded_item.etag());
        assert_eq!(item.meta()?, loaded_item.meta()?);
        verify_item(&loaded_item, &meta, content)?;
    }

    // Without content
    {
        let saved_col = col_mgr.cache_save(&col)?;
        let loaded_col = col_mgr.cache_load(&saved_col)?;
        assert_eq!(col.uid(), loaded_col.uid());
        assert_eq!(col.etag(), loaded_col.etag());
        assert_eq!(col.meta()?, loaded_col.meta()?);

        let saved_item = it_mgr.cache_save(&item)?;
        let loaded_item = it_mgr.cache_load(&saved_item)?;
        assert_eq!(item.uid(), loaded_item.uid());
        assert_eq!(item.etag(), loaded_item.etag());
        assert_eq!(item.meta()?, loaded_item.meta()?);
    }

    etebase.logout()
}
