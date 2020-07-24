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
        user: &etebase::User {
            username: user.username,
            email: user.email,
        },
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

    // FIXME: move to prepare user for test
    let client = Client::new(CLIENT_NAME, &test_url())?;
    let session_key = from_base64(sessionStorageKey)?;

    let mut ret = Account::restore(client, user.storedSession, Some(&session_key))?;
    ret.force_api_base(&test_url())?;
    ret.fetch_token()?;

    Ok(ret)
}

fn verify_collection(col: &Collection, meta: &CollectionMetadata, content: &[u8]) -> Result<()> {
    col.verify()?;
    assert_eq!(&col.decrypt_meta()?, meta);
    assert_eq!(col.decrypt_content()?, content);
    Ok(())
}

fn verify_item(item: &Item, meta: &ItemMetadata, content: &[u8]) -> Result<()> {
    item.verify()?;
    assert_eq!(&item.decrypt_meta()?, meta);
    assert_eq!(item.decrypt_content()?, content);
    Ok(())
}

#[test]
fn simple_collection_handling() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc"));
    let content = b"SomeContent";

    let mut col = col_mgr.create(&meta, content)?;
    verify_collection(&col, &meta, content)?;

    let meta2 = meta.clone().set_name("Collection meta2");
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

    let meta = ItemMetadata::new().set_name(Some("Item 1"));
    let content = b"ItemContent";
    let mut item = it_mgr.create(&meta, content)?;
    verify_item(&item, &meta, content)?;

    let meta2 = ItemMetadata::new().set_name(Some("Item 2"));
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
    let meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc"));
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

    let meta2 = meta.clone().set_name("Collection meta2");
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

        assert_err!(col_mgr.transaction(&col, None), Error::Http(_));
        let fetch_options = FetchOptions::new().stoken(col_old.stoken());
        assert_err!(col_mgr.upload(&col, Some(&fetch_options)), Error::Http(_));
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
    let col_meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc"));
    let col_content = b"SomeContent";

    let col = col_mgr.create(&col_meta, col_content)?;

    col_mgr.upload(&col, None)?;

    let it_mgr = col_mgr.item_manager(&col)?;

    let meta = ItemMetadata::new().set_name(Some("Item 1"));
    let content = b"Content 1";

    let mut item = it_mgr.create(&meta, content)?;

    it_mgr.batch(iter::once(&item), None)?;

    {
        let items = it_mgr.list(None)?;
        assert_eq!(items.data().len(), 1);
        verify_item(&items.data().first().unwrap(), &meta, content)?;
    }

    let mut item_old = it_mgr.fetch(item.uid(), None)?;

    let meta2 = ItemMetadata::new().set_name(Some("Item 2"));
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
        assert_err!(it_mgr.transaction(iter::once(&item_old), None), Error::Http(_));
    }

    let content2 = b"Content 2";
    item.set_content(content2)?;

    {
        let fetch_options = FetchOptions::new().stoken(col_old.stoken());
        assert_err!(it_mgr.batch(iter::once(&item), Some(&fetch_options)), Error::Http(_));
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
    let col_meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc"));
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
        let meta = col.item()?.decrypt_meta()?;
        let first_item = items.data().first().unwrap();
        verify_item(&first_item, &meta, col_content)?;
        // Also verify the collection metadata is good
        assert_eq!(&first_item.decrypt_meta_generic::<CollectionMetadata>()?, &col_meta);
    }

    let meta = ItemMetadata::new();
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
        let meta = col.item()?.decrypt_meta()?;
        let first_item = updates.data().first().unwrap();
        verify_item(&first_item, &meta, col_content2)?;
        // Also verify the collection metadata is good
        assert_eq!(&first_item.decrypt_meta_generic::<CollectionMetadata>()?, &col_meta);
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

    let meta = ItemMetadata::new().set_name(Some("Item 1"));
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

    let meta = ItemMetadata::new().set_name(Some("Item 1"));
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
            let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i)));
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
    let meta = ItemMetadata::new().set_name(Some("Item 1"));
    let content = b"";
    let mut item = it_mgr.create(&meta, content)?;

    let deps = vec![&item];
    it_mgr.transaction(deps.clone().into_iter(), None)?;

    let item_old = it_mgr.fetch(item.uid(), None)?;
    let mut item_old2 = it_mgr.fetch(item.uid(), None)?;

    let items: Vec<Item> = (0..5).into_iter()
        .map(|i| {
            let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i)));
            let content = b"";
            it_mgr.create(&meta, content).unwrap()
        })
        .collect();

    it_mgr.transaction_deps(items.iter(), deps.clone().into_iter(), None)?;

    {
        let items = it_mgr.list(None)?;
        assert_eq!(items.data().len(), 6);
    }

    let meta2 = ItemMetadata::new().set_name(Some("some"));
    item.set_meta(&meta2)?;
    let deps = vec![&item];

    it_mgr.transaction_deps(iter::once(&item), deps.clone().into_iter(), None)?;

    {
        let items = it_mgr.list(None)?;
        assert_eq!(items.data().len(), 6);
    }

    {
        let meta3 = ItemMetadata::new().set_name(Some("some2"));
        item.set_meta(&meta3)?;

        let deps2 = items.iter().chain(iter::once(&item_old));

        // Old in the deps
        assert_err!(it_mgr.transaction_deps(iter::once(&item), deps2.into_iter(), None), Error::Http(_));
        it_mgr.transaction(iter::once(&item), None)?;

        item_old2.set_meta(&meta3)?;

        // Old stoken in the item itself
        assert_err!(it_mgr.transaction(iter::once(&item_old2), None), Error::Http(_));
    }

    {
        let meta3 = ItemMetadata::new().set_name(Some("some3"));
        let mut item2 = it_mgr.fetch(items[0].uid(), None)?;
        item2.set_meta(&meta3)?;

        item_old2.set_meta(&meta3)?;

        // Part of the transaction is bad, and part is good
        assert_err!(it_mgr.transaction(vec![&item2, &item_old2].into_iter(), None), Error::Http(_));

        // Verify it hasn't changed after the transaction above failed
        let item2_fetch = it_mgr.fetch(item2.uid(), None)?;
        assert_ne!(item2_fetch.decrypt_meta()?, item2.decrypt_meta()?);
    }

    {
        // Global stoken test
        let meta3 = ItemMetadata::new().set_name(Some("some4"));
        item.set_meta(&meta3)?;

        let new_col = col_mgr.fetch(col.uid(), None)?;
        let stoken = new_col.stoken();
        let bad_etag = col.etag();

        let fetch_options = FetchOptions::new().stoken(bad_etag.as_deref());
        assert_err!(it_mgr.transaction(iter::once(&item), Some(&fetch_options)), Error::Http(_));

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
    let meta = ItemMetadata::new().set_name(Some("Item Orig"));
    let content = b"";
    let mut item = it_mgr.create(&meta, content)?;

    it_mgr.batch(iter::once(&item), None)?;

    let mut item2 = it_mgr.fetch(item.uid(), None)?;

    let items: Vec<Item> = (0..5).into_iter()
        .map(|i| {
            let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i)));
            let content = b"";
            it_mgr.create(&meta, content).unwrap()
        })
        .collect();

    it_mgr.batch(items.iter(), None)?;

    {
        let meta3 = ItemMetadata::new().set_name(Some("some2"));
        item2.set_meta(&meta3)?;
        it_mgr.batch(iter::once(&item2), None)?;

        let meta3 = ItemMetadata::new().set_name(Some("some3"));
        item.set_meta(&meta3)?;

        // Old stoken in the item itself should work for batch and fail for transaction or batch with deps
        assert_err!(it_mgr.transaction(iter::once(&item), None), Error::Http(_));
        assert_err!(it_mgr.batch_deps(iter::once(&item), iter::once(&item), None), Error::Http(_));

        it_mgr.batch(iter::once(&item), None)?;
    }

    {
        // Global stoken test
        let meta3 = ItemMetadata::new().set_name(Some("some4"));
        item.set_meta(&meta3)?;

        let new_col = col_mgr.fetch(col.uid(), None)?;
        let stoken = new_col.stoken();
        let bad_etag = col.etag();

        let fetch_options = FetchOptions::new().stoken(bad_etag.as_deref());
        assert_err!(it_mgr.batch(iter::once(&item), Some(&fetch_options)), Error::Http(_));

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
    let meta = ItemMetadata::new().set_name(Some("Item Orig"));
    let content = b"";
    let item = it_mgr.create(&meta, content)?;

    it_mgr.batch(iter::once(&item), None)?;

    let items: Vec<Item> = (0..5).into_iter()
        .map(|i| {
            let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i)));
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
        let meta3 = ItemMetadata::new().set_name(Some("some2"));
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
    let meta = ItemMetadata::new().set_name(Some("Item Orig"));
    let content = b"";
    let mut item = it_mgr.create(&meta, content)?;

    for i in 0..5 {
        let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i)));
        item.set_meta(&meta)?;
        it_mgr.batch(iter::once(&item), None)?;
    }

    {
        let meta = ItemMetadata::new().set_name(Some("Latest"));
        item.set_meta(&meta)?;
        it_mgr.batch(iter::once(&item), None)?;
    }

    {
        let etag = item.etag();
        let fetch_options = FetchOptions::new().iterator(etag.as_deref());
        let revisions = it_mgr.item_revisions(&item, Some(&fetch_options))?;
        assert_eq!(revisions.data().len(), 5);
        assert!(revisions.done());

        let etag = item.etag();
        let fetch_options = FetchOptions::new().iterator(etag.as_deref()).limit(5);
        let revisions = it_mgr.item_revisions(&item, Some(&fetch_options))?;
        assert_eq!(revisions.data().len(), 5);
        assert!(revisions.done());

        for i in 0..5 {
            let meta = ItemMetadata::new().set_name(Some(&format!("Item {}", i)));
            let rev = &revisions.data()[4 - i];
            assert_eq!(&rev.decrypt_meta()?, &meta);
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
fn chunking_large_data() -> Result<()> {
    let etebase = init_test(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let col_meta = CollectionMetadata::new("type", "Collection").set_description(Some("Mine")).set_color(Some("#aabbcc"));
    let col_content = b"SomeContent";

    let col = col_mgr.create(&col_meta, col_content)?;

    col_mgr.upload(&col, None)?;

    let it_mgr = col_mgr.item_manager(&col)?;

    let meta = ItemMetadata::new();
    let content = randombytes_deterministic(120 * 1024, &[0; 32]); // 120kb of pseuedorandom data

    let mut item = it_mgr.create(&meta, &content)?;
    verify_item(&item, &meta, &content)?;

    let mut uid_set = HashSet::new();

    // Get the first chunks and init uid_set
    {
        let chunks = chunk_uids(&item);
        assert_eq!(chunks.len(), 7);
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
        assert_eq!(chunks.len(), 7);

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
    let etebase = init_test(&USER)?;
    etebase.logout()?;

    let another_password = "AnotherPassword";
    let client = Client::new(CLIENT_NAME, &test_url())?;
    let mut etebase2 = Account::login(client.clone(), USER2.username, USER2.password)?;

    etebase2.change_password(another_password)?;

    etebase2.logout()?;

    assert_err!(Account::login(client.clone(), USER2.username, "BadPassword"), Error::Http(_));

    // FIXME: add tests to verify that we can actually manipulate the data
    let mut etebase2 = Account::login(client.clone(), USER2.username, another_password)?;

    etebase2.change_password(USER2.password)?;

    etebase2.logout()
}


#[test]
fn session_save_and_restore() -> Result<()> {
    let client = Client::new(CLIENT_NAME, &test_url())?;
    let etebase = init_test(&USER)?;

    // Verify we can store and restore without an encryption key
    {
        let saved = etebase.save(None)?;
        let mut etebase2 = Account::restore(client.clone(), &saved, None)?;

        // FIXME: we should verify we can access data instead
        &etebase2.fetch_token()?;
    }

    // Verify we can store and restore with an encryption key
    {
        let key = etebase::utils::randombytes(32);
        let saved = etebase.save(Some(&key))?;
        let mut etebase2 = Account::restore(client.clone(), &saved, Some(&key))?;

        // FIXME: we should verify we can access data instead
        &etebase2.fetch_token()?;
    }

    etebase.logout()
}
