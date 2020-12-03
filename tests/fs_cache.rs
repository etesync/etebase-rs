// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::env;

const CLIENT_NAME: &str = "etebase-tests";

fn test_url() -> String {
    env::var("ETEBASE_TEST_API_URL").unwrap_or("http://localhost:8033".to_owned())
}

use std::path::{
    Path,
    PathBuf,
};
use std::io;

use remove_dir_all::remove_dir_all;

use etebase::error::Result;


use etebase::{
    Account,
    Client,
    ItemMetadata,
    fs_cache::FileSystemCache,
    utils::{
        from_base64,
        to_base64,
        randombytes,
    },
};

#[allow(dead_code)]
mod common;

use common::{
    USER,
    TestUser,
    sessionStorageKey,
};

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new() -> io::Result<TempDir> {
        etebase::init().unwrap();

        let tmpdir = env::temp_dir();
        let randbytes = randombytes(10);
        let rand = to_base64(&randbytes).unwrap();
        let name = format!("etebase-test-{}", rand);

        let path = tmpdir.join(&name);
        match std::fs::create_dir(&path) {
            Ok(_) => return Ok(TempDir { path }),
            Err(e) => return Err(e),
        }
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        remove_dir_all(&self.path).unwrap();
    }
}

fn init_test_local(user: &TestUser) -> Result<Account> {
    etebase::init()?;

    let client = Client::new(CLIENT_NAME, &test_url())?;
    let session_key = from_base64(sessionStorageKey)?;

    let ret = Account::restore(client, user.storedSession, Some(&session_key))?;

    Ok(ret)
}

#[test]
fn simple_cache_handling() -> Result<()> {
    let client = Client::new(CLIENT_NAME, &test_url())?;
    let etebase = init_test_local(&USER)?;
    let col_mgr = etebase.collection_manager()?;
    let meta = ItemMetadata::new().set_name("Collection").set_description("Mine").set_color("#aabbcc").clone();
    let content = b"SomeContent";

    let col = col_mgr.create("some.coltype", &meta, content)?;

    let temp_dir = TempDir::new()?;
    let fs_cache = FileSystemCache::new(temp_dir.path(), USER.username)?;

    assert!(fs_cache.load_account(&client, None).is_err());
    fs_cache.save_account(&etebase, None)?;
    fs_cache.load_account(&client, None)?;

    assert!(fs_cache.load_stoken()?.is_none());
    fs_cache.save_stoken("test")?;
    assert_eq!(fs_cache.load_stoken()?.unwrap(), "test");
    fs_cache.save_stoken("test2")?;
    assert_eq!(fs_cache.load_stoken()?.unwrap(), "test2");

    assert!(fs_cache.collection(&col_mgr, col.uid()).is_err());
    fs_cache.collection_set_with_content(&col_mgr, &col)?;
    let col2 = fs_cache.collection(&col_mgr, col.uid())?;
    assert_eq!(col2.meta_raw()?, col.meta_raw()?);
    assert_eq!(col2.content()?, col.content()?);

    assert!(fs_cache.collection_load_stoken(col.uid())?.is_none());
    fs_cache.collection_save_stoken(col.uid(), "test")?;
    assert_eq!(fs_cache.collection_load_stoken(col.uid())?.unwrap(), "test");
    fs_cache.collection_save_stoken(col.uid(), "test2")?;
    assert_eq!(fs_cache.collection_load_stoken(col.uid())?.unwrap(), "test2");

    fs_cache.collection_unset(&col_mgr, col.uid())?;
    assert!(fs_cache.collection(&col_mgr, col.uid()).is_err());
    assert!(fs_cache.collection_load_stoken(col.uid())?.is_none());


    fs_cache.collection_set_with_content(&col_mgr, &col)?;
    let item_mgr = col_mgr.item_manager(&col)?;
    let item = {
        let meta = ItemMetadata::new().set_name("Item 1").clone();
        let content = b"Content 1";
        item_mgr.create(&meta, content)?
    };

    assert!(fs_cache.item(&item_mgr, col.uid(), item.uid()).is_err());
    fs_cache.item_set_with_content(&item_mgr, col.uid(), &item)?;
    let item2 = fs_cache.item(&item_mgr, col.uid(), item.uid())?;
    assert_eq!(item2.meta_raw()?, item.meta_raw()?);
    assert_eq!(item2.content()?, item.content()?);

    let item = {
        let meta = ItemMetadata::new().set_name("Item 2").clone();
        let content = b"Content 2";
        item_mgr.create(&meta, content)?
    };
    fs_cache.item_set_with_content(&item_mgr, col.uid(), &item)?;

    let cache_response = fs_cache.collection_list_raw()?;
    assert_eq!(1, cache_response.count());

    let cache_response = fs_cache.item_list_raw(col.uid())?;
    assert_eq!(2, cache_response.count());

    fs_cache.item_unset(&item_mgr, col.uid(), item.uid())?;
    assert!(fs_cache.item(&item_mgr, col.uid(), item.uid()).is_err());

    fs_cache.clear_user_cache()?;

    Ok(())
}
