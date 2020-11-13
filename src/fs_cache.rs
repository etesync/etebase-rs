// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::fs;
use std::path::{
    Path,
    PathBuf,
};
use remove_dir_all::remove_dir_all;
use super::{
    http_client::Client,
    service::{
        Account,
        CollectionManager,
        Collection,
        ItemManager,
        Item,
    },
    error::Result,
};

/*
File structure:
cache_dir/
    user1/ <-- the name of the user
        account <-- the account cache
        stoken <-- the stokens of the collection fetch
        cols/
            UID1/ <-- The uid of the first col
                ...
            UID2/ <-- The uid of the second col
                col <-- the col itself
                stoken <-- the stoken of the items fetch
                items/
                    item_uid1 <-- the item with uid 1
                    item_uid2
                    ...
 */
pub struct FileSystemCache {
    user_dir: PathBuf,
    cols_dir: PathBuf,
}


impl FileSystemCache {
    /// Initialize a file system cache object
    ///
    /// # Arguments:
    /// * `path` - the path to a directory to store cache in
    /// * `username` - username of the user to cache data for
    pub fn new(path: &Path, username: &str) -> Result<Self> {
        let mut user_dir = PathBuf::from(path);
        user_dir.push(username);
        let cols_dir = user_dir.join("cols");
        fs::create_dir_all(&cols_dir)?;

        Ok(Self {
            user_dir,
            cols_dir,
        })
    }

    fn get_collection_items_dir(&self, col_uid: &str) -> PathBuf {
        self.cols_dir.join(col_uid).join("items")
    }

    /// Clear all cache for the user
    pub fn clear_user_cache(&self) -> Result<()> {
        let user_dir = &self.user_dir;
        remove_dir_all(user_dir)?;
        Ok(())
    }

    /// Save the user account
    ///
    /// Load it later using [Self::load_account]
    ///
    /// # Arguments:
    /// * `etebase` - the account to save
    /// * `encryption_key` - used to encrypt the saved account string to enhance security
    pub fn save_account(&self, etebase: &Account, encryption_key: Option<&[u8]>) -> Result<()> {
        let account_file = self.user_dir.join("account");
        let account = etebase.save(encryption_key)?;
        fs::write(account_file, account)?;
        Ok(())
    }

    /// Load the [Account] object from cache
    ///
    /// # Arguments:
    /// * `client` - the already setup [Client] object
    /// * `encryption_key` - the same encryption key passed to [Self::save_account] while saving the account
    pub fn load_account(&self, client: &Client, encryption_key: Option<&[u8]>) -> Result<Account> {
        let account_file = self.user_dir.join("account");
        let data = fs::read_to_string(account_file)?;
        Account::restore(client.clone(), &data, encryption_key)
    }

    /// Save the collection list sync token
    ///
    /// # Arguments:
    /// * `stoken` - the sync token to be saved
    pub fn save_stoken(&self, stoken: &str) -> Result<()> {
        let stoken_file = self.user_dir.join("stoken");
        fs::write(stoken_file, stoken)?;
        Ok(())
    }

    /// Load the collection list sync token from cache
    pub fn load_stoken(&self) -> Result<Option<String>> {
        let stoken_file = self.user_dir.join("stoken");
        let ret = fs::read_to_string(stoken_file);
        match ret {
            Err(_) => Ok(None),
            Ok(ret) => Ok(Some(ret)),
        }
    }

    /// Save a collection's sync token
    ///
    /// # Arguments:
    /// * `col_uid` - the UID of the collection
    /// * `stoken` - the sync token to be saved
    pub fn collection_save_stoken(&self, col_uid: &str, stoken: &str) -> Result<()> {
        let stoken_file = self.cols_dir.join(col_uid).join("stoken");
        fs::write(stoken_file, stoken)?;
        Ok(())
    }

    /// Load the sync token for a collection
    ///
    /// # Arguments:
    /// * `col_uid` - the UID of the collection
    pub fn collection_load_stoken(&self, col_uid: &str) -> Result<Option<String>> {
        let stoken_file = self.cols_dir.join(col_uid).join("stoken");
        let ret = fs::read_to_string(stoken_file);
        match ret {
            Err(_) => Ok(None),
            Ok(ret) => Ok(Some(ret)),
        }
    }

    /// Raw data of all cached collections as a list response
    pub fn collection_list_raw(&self) -> Result<ListRawCacheResponse> {
        let ret = fs::read_dir(&self.cols_dir)?;
        Ok(ListRawCacheResponse { inner_iter: ret, is_collection: true } )
    }

    /// Load a collection from cache
    ///
    /// # Arguments:
    /// * `col_mgr` - collection manager for the account
    /// * `col_uid` - the UID of the collection
    pub fn collection(&self, col_mgr: &CollectionManager, col_uid: &str) -> Result<Collection> {
        let col_file = self.cols_dir.join(col_uid).join("col");
        let content = fs::read(col_file)?;
        col_mgr.cache_load(&content)
    }

    /// Save a collection to cache
    ///
    /// # Arguments:
    /// * `col_mgr` - collection manager for the account
    /// * `collection` - the collection to be saved
    pub fn collection_set(&self, col_mgr: &CollectionManager, collection: &Collection) -> Result<()> {
        let mut col_file = self.cols_dir.join(collection.uid());
        fs::create_dir_all(&col_file)?;
        col_file.push("col");

        let content = col_mgr.cache_save(collection)?;
        fs::write(col_file, &content)?;

        let items_dir = self.get_collection_items_dir(collection.uid());
        fs::create_dir_all(&items_dir)?;

        Ok(())
    }

    /// Save a collection and its content to cache
    ///
    /// # Arguments:
    /// * `col_mgr` - collection manager for the account
    /// * `collection` - the collection to be saved
    pub fn collection_set_with_content(&self, col_mgr: &CollectionManager, collection: &Collection) -> Result<()> {
        let mut col_file = self.cols_dir.join(collection.uid());
        fs::create_dir_all(&col_file)?;
        col_file.push("col");

        let content = col_mgr.cache_save_with_content(collection)?;
        fs::write(col_file, &content)?;

        let items_dir = self.get_collection_items_dir(collection.uid());
        fs::create_dir_all(&items_dir)?;

        Ok(())
    }

    /// Remove a collection from cache
    ///
    /// # Arguments:
    /// * `_col_mgr` - collection manager for the account
    /// * `col_uid` - the UID of the collection to be unset
    pub fn collection_unset(&self, _col_mgr: &CollectionManager, col_uid: &str) -> Result<()> {
        let col_dir = self.cols_dir.join(col_uid);
        remove_dir_all(col_dir)?;
        Ok(())
    }

    /// Return a list of cached items in a collection
    ///
    /// # Arguments:
    /// * `col_uid` - the UID of the parent collection
    pub fn item_list_raw(&self, col_uid: &str) -> Result<ListRawCacheResponse> {
        let items_dir = self.get_collection_items_dir(col_uid);
        let ret = fs::read_dir(items_dir)?;
        Ok(ListRawCacheResponse { inner_iter: ret, is_collection: false } )
    }

    /// Load an item from cache
    ///
    /// # Arguments:
    /// * `item_mgr` - item manager for the parent collection
    /// * `col_uid` - the UID of the parent collection
    /// * `item_uid` - the UID of the item
    pub fn item(&self, item_mgr: &ItemManager, col_uid: &str, item_uid: &str) -> Result<Item> {
        let item_file = self.get_collection_items_dir(col_uid).join(item_uid);
        let content = fs::read(item_file)?;
        item_mgr.cache_load(&content)
    }

    /// Save an item to cache
    ///
    /// # Arguments:
    /// * `item_mgr` - item manager for the parent collection
    /// * `col_uid` - the UID of the parent collection
    /// * `item` - the item to be saved
    pub fn item_set(&self, item_mgr: &ItemManager, col_uid: &str, item: &Item) -> Result<()> {
        let item_file = self.get_collection_items_dir(col_uid).join(item.uid());
        let content = item_mgr.cache_save(item)?;
        fs::write(item_file, &content)?;
        Ok(())
    }

    /// Save an item and its content to cache
    ///
    /// # Arguments:
    /// * `item_mgr` - item manager for the parent collection
    /// * `col_uid` - the UID of the parent collection
    /// * `item` - the item to be saved
    pub fn item_set_with_content(&self, item_mgr: &ItemManager, col_uid: &str, item: &Item) -> Result<()> {
        let item_file = self.get_collection_items_dir(col_uid).join(item.uid());
        let content = item_mgr.cache_save_with_content(item)?;
        fs::write(item_file, &content)?;
        Ok(())
    }

    /// Remove an item from cache
    ///
    /// # Arguments:
    /// * `_item_mgr` - item manager for the parent collection
    /// * `col_uid` - the UID of the parent collection
    /// * `item_uid` - the UID of the item
    pub fn item_unset(&self, _item_mgr: &ItemManager, col_uid: &str, item_uid: &str) -> Result<()> {
        let item_file = self.get_collection_items_dir(col_uid).join(item_uid);
        fs::remove_file(item_file)?;
        Ok(())
    }
}

/// An iterator used for cache list responses
pub struct ListRawCacheResponse {
    inner_iter: fs::ReadDir,
    is_collection: bool,
}

impl Iterator for ListRawCacheResponse {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_iter.next().map(|x| -> Result<Vec<u8>> {
            let mut col_file = x?.path();
            if self.is_collection {
                col_file.push("col");
            }
            Ok(fs::read(col_file)?)
        })
    }
}
