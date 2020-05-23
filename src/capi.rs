// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

extern crate openssl;
extern crate base64;

use std::os::raw::c_char;
use std::ffi::{CString, CStr};

use super::{
    crypto::{
        gen_uid,
        CURRENT_VERSION,
        derive_key,
        AsymmetricKeyPair,
        CryptoManager,
    },
    service::{
        test_reset,
        Client,
        Authenticator,
        JournalManager,
        Journal,
        EntryManager,
        Entry,
        UserInfoManager,
        UserInfo,
    },
    content::{
        DEFAULT_COLOR,
        CollectionInfo,
        SyncEntry,
    },
    error:: {
        Result,
    },
};

macro_rules! try_null {
    ($x:expr) => {
        match $x {
            Ok(val) => val,
            Err(_e) => return std::ptr::null_mut(),
        };
    };
}

fn res_to_c_ret<T>(res: Result<T>) -> i32 {
    match res {
        Ok(_) => 0,
        Err(_e) => -1,
    }
}

#[no_mangle]
pub static ETESYNC_CURRENT_VERSION: u8 = CURRENT_VERSION;

#[no_mangle]
pub static ETESYNC_COLLECTION_DEFAULT_COLOR: i32 = DEFAULT_COLOR;

#[no_mangle]
pub extern fn etesync_get_server_url() -> *const c_char {
    // FIXME: find a way to not clone SERVICE_API_URL,
    let service_url: *const u8 = b"https://api.etesync.com\0".as_ptr();
    return service_url as *const c_char;
}

#[no_mangle]
pub struct EteSync {
    client: Client,
}

/// Creates a new EteSync client with specified client_name and server_url
#[no_mangle]
pub extern fn etesync_new(client_name: *const c_char, server_url: *const c_char) -> *mut EteSync {
    let server_url = (unsafe { CStr::from_ptr(server_url) }).to_string_lossy();
    let client_name = (unsafe { CStr::from_ptr(client_name) }).to_string_lossy();

    Box::into_raw(
        Box::new(EteSync {
            client: try_null!(Client::new(&client_name, &server_url[..], None)),
        })
    )
}

/// Sets specified auth token in the client
#[no_mangle]
pub extern fn etesync_set_auth_token(etesync: &mut EteSync, token: *const c_char) {
    let token = (unsafe { CStr::from_ptr(token) }).to_string_lossy();

    etesync.client.set_token(&token[..])
}

/// Destroys the EteSync client object
#[no_mangle]
pub extern fn etesync_destroy(etesync: &mut EteSync) {
    let etesync = unsafe { Box::from_raw(etesync) };
    drop(etesync);
}

#[no_mangle]
pub extern fn etesync_test_reset(etesync: &EteSync) -> i32 {
    res_to_c_ret(test_reset(&etesync.client))
}

/// Uses salt and password to derive a key. This is used for encryption and decryption.
#[no_mangle]
pub extern fn etesync_crypto_derive_key(_etesync: &EteSync, salt: *const c_char, password: *const c_char) -> *mut c_char {
    let salt = (unsafe { CStr::from_ptr(salt) }).to_string_lossy();
    let password = (unsafe { CStr::from_ptr(password) }).to_string_lossy();

    let derived = try_null!(derive_key(&salt, &password));

    try_null!(CString::new(base64::encode(&derived))).into_raw()
}

/// Generates a random unique ID
#[no_mangle]
pub extern fn etesync_gen_uid() -> *mut c_char {
    let uid = try_null!(gen_uid());
    try_null!(CString::new(uid)).into_raw()
}

/// Generates a new RSA keypair
#[no_mangle]
pub extern fn etesync_crypto_generate_keypair(_etesync: &EteSync) -> *mut AsymmetricKeyPair {
    let keypair = try_null!(AsymmetricKeyPair::generate_keypair());

    Box::into_raw(
        Box::new(keypair)
    )
}

/// Gets auth token for the user with specified credentials. This authenticates the user to the server.
#[no_mangle]
pub extern fn etesync_auth_get_token(etesync: &EteSync, username: *const c_char, password: *const c_char) -> *mut c_char {
    let username = (unsafe { CStr::from_ptr(username) }).to_string_lossy();
    let password = (unsafe { CStr::from_ptr(password) }).to_string_lossy();

    let authenticator = Authenticator::new(&etesync.client);
    let token = try_null!(authenticator.get_token(&username, &password));

    try_null!(CString::new(&token[..])).into_raw()
}

/// Invalidates specified token. This ends the current user session.
#[no_mangle]
pub extern fn etesync_auth_invalidate_token(etesync: &EteSync, token: *const c_char) -> i32 {
    let token = (unsafe { CStr::from_ptr(token) }).to_string_lossy();

    let authenticator = Authenticator::new(&etesync.client);
    res_to_c_ret(authenticator.invalidate_token(&token))
}

/// Returns a new journal manager
#[no_mangle]
pub extern fn etesync_journal_manager_new(etesync: &EteSync) -> *mut JournalManager {
    let journal_manager = JournalManager::new(&etesync.client);

    Box::into_raw(
        Box::new(journal_manager)
    )
}

/// Destroys specified journal manager object
#[no_mangle]
pub extern fn etesync_journal_manager_destroy(journal_manager: &mut JournalManager) {
    let journal_manager = unsafe { Box::from_raw(journal_manager) };
    drop(journal_manager);
}

/// Gets journal with specified uid
#[no_mangle]
pub extern fn etesync_journal_manager_fetch(journal_manager: &JournalManager, journal_uid: *const c_char) -> *mut Journal {
    let journal_uid = (unsafe { CStr::from_ptr(journal_uid) }).to_string_lossy();
    let journal = try_null!(journal_manager.fetch(&journal_uid));

    Box::into_raw(
        Box::new(journal)
    )
}

/// Gets a list of all journals
#[no_mangle]
pub extern fn etesync_journal_manager_list(journal_manager: &JournalManager) -> *mut *mut Journal {
    let journals = try_null!(journal_manager.list());
    let mut journals: Vec<*mut Journal> = journals.into_iter().map(|journal| {
        Box::into_raw(
            Box::new(journal)
        )
    }).collect();
    journals.push(std::ptr::null_mut());

    let ret = journals.as_mut_ptr();
    std::mem::forget(journals);

    ret
}

/// Creates the specified journal
#[no_mangle]
pub extern fn etesync_journal_manager_create(journal_manager: &JournalManager, journal: &Journal) -> i32 {
    res_to_c_ret(journal_manager.create(&journal))
}

/// Updates the specified journal 
#[no_mangle]
pub extern fn etesync_journal_manager_update(journal_manager: &JournalManager, journal: &Journal) -> i32 {
    res_to_c_ret(journal_manager.update(&journal))
}

/// Deletes the specified journal
#[no_mangle]
pub extern fn etesync_journal_manager_delete(journal_manager: &JournalManager, journal: &Journal) -> i32 {
    res_to_c_ret(journal_manager.delete(&journal))
}

/// Returns a new local journal
#[no_mangle]
pub extern fn etesync_journal_new(uid: *const c_char, version: u8) -> *mut Journal {
    let uid = (unsafe { CStr::from_ptr(uid) }).to_string_lossy();
    let journal = Journal::new(&uid[..], version);

    Box::into_raw(
        Box::new(journal)
    )
}

/// Returns the uid of the specified journal
#[no_mangle]
pub extern fn etesync_journal_get_uid(journal: &Journal) -> *mut c_char {
    try_null!(CString::new(&journal.uid[..])).into_raw()
}

/// Returns the version of the specified journal
#[no_mangle]
pub extern fn etesync_journal_get_version(journal: &Journal) -> u8 {
    journal.version
}

/// Returns the owner of the specified journal
#[no_mangle]
pub extern fn etesync_journal_get_owner(journal: &Journal) -> *mut c_char {
    journal.owner.as_ref()
        .and_then(|owner| Some(CString::new(&owner[..]).unwrap().into_raw()))
        .unwrap_or(std::ptr::null_mut())
}

/// Returns whether the journal is read-only or not
#[no_mangle]
pub extern fn etesync_journal_is_read_only(journal: &Journal) -> bool {
    journal.is_read_only()
}

/// Returns the uid of the last entry in the journal
#[no_mangle]
pub extern fn etesync_journal_get_last_uid(journal: &Journal) -> *mut c_char {
    journal.get_last_uid().as_ref()
        .and_then(|last_uid| Some(CString::new(&last_uid[..]).unwrap().into_raw()))
        .unwrap_or(std::ptr::null_mut())
}

/// Returns decrypted information about the journal
#[no_mangle]
pub extern fn etesync_journal_get_info(journal: &Journal, crypto_manager: &CryptoManager) -> *mut CollectionInfo {
    let info = try_null!(journal.get_info(&crypto_manager));

    Box::into_raw(
        Box::new(info)
    )
}

/// Encrypts and stores provided collection info into the journal
#[no_mangle]
pub extern fn etesync_journal_set_info(journal: &mut Journal, crypto_manager: &CryptoManager, info: &CollectionInfo) -> i32 {
    res_to_c_ret(journal.set_info(&crypto_manager, &info))
}

/// Returns a new cypto manager object for the provided journal. Uses key if journal is symmetrically encrypted. Otherwise, uses RSA to decrypt key stored in the journal.
#[no_mangle]
pub extern fn etesync_journal_get_crypto_manager(journal: &Journal, key: *const c_char, keypair: &AsymmetricKeyPair) -> *mut CryptoManager {
    let key = (unsafe { CStr::from_ptr(key) }).to_string_lossy();
    let key = try_null!(base64::decode(&key[..]));
    let crypto_manager = try_null!(journal.get_crypto_manager(&key, &keypair));

    Box::into_raw(
        Box::new(crypto_manager)
    )
}

/// Destroys the journal object
#[no_mangle]
pub extern fn etesync_journal_destroy(journal: &mut Journal) {
    let journal = unsafe { Box::from_raw(journal) };
    drop(journal);
}

/// Destroys the cypto manager object
#[no_mangle]
pub extern fn etesync_crypto_manager_destroy(crypto_manager: *mut CryptoManager) {
    let crypto_manager = unsafe { Box::from_raw(crypto_manager) };
    drop(crypto_manager);
}

/// Returns a new collection info object with provided fields
#[no_mangle]
pub extern fn etesync_collection_info_new(col_type: *const c_char, display_name: *const c_char, description: *const c_char, color: i32) -> *mut CollectionInfo {
    let col_type = (unsafe { CStr::from_ptr(col_type) }).to_string_lossy().to_string();
    let display_name = (unsafe { CStr::from_ptr(display_name) }).to_string_lossy().to_string();
    let description = unsafe {
        description.as_ref().and_then(|description| Some(CStr::from_ptr(description).to_string_lossy().to_string()))
    };

    let info = CollectionInfo {
        col_type,
        display_name,
        description,
        color: Some(color),
    };

    Box::into_raw(
        Box::new(info)
    )
}

/// Returns the collection type
#[no_mangle]
pub extern fn etesync_collection_info_get_type(info: &CollectionInfo) -> *mut c_char {
    try_null!(CString::new(&info.col_type[..])).into_raw()
}

/// Returns the collection display name
#[no_mangle]
pub extern fn etesync_collection_info_get_display_name(info: &CollectionInfo) -> *mut c_char {
    try_null!(CString::new(&info.display_name[..])).into_raw()
}

/// Returns the collection description
#[no_mangle]
pub extern fn etesync_collection_info_get_description(info: &CollectionInfo) -> *mut c_char {
    info.description.as_ref()
        .and_then(|description| Some(CString::new(&description[..]).unwrap().into_raw()))
        .unwrap_or(std::ptr::null_mut())
}

/// Returns the collection color
#[no_mangle]
pub extern fn etesync_collection_info_get_color(info: &CollectionInfo) -> i32 {
    info.color.unwrap_or(DEFAULT_COLOR)
}

/// Destroys the collection info object
#[no_mangle]
pub extern fn etesync_collection_info_destroy(info: &mut CollectionInfo) {
    let info = unsafe { Box::from_raw(info) };
    drop(info);
}


/// Returns a new entry manager for journal with specified uid
#[no_mangle]
pub extern fn etesync_entry_manager_new(etesync: &EteSync, journal_uid: *const c_char) -> *mut EntryManager {
    let journal_uid = (unsafe { CStr::from_ptr(journal_uid) }).to_string_lossy();
    let entry_manager = EntryManager::new(&etesync.client, &journal_uid);

    Box::into_raw(
        Box::new(entry_manager)
    )
}

/// Gets a list of "limit" number of entries after prev_uid
#[no_mangle]
pub extern fn etesync_entry_manager_list(entry_manager: &EntryManager, prev_uid: *const c_char, limit: usize) -> *mut *mut Entry {
    let prev_uid = unsafe {
        prev_uid.as_ref().and_then(|prev_uid| Some(CStr::from_ptr(prev_uid).to_string_lossy().to_string()))
    };
    let limit = if limit == 0 {
        None
    } else {
        Some(limit)
    };

    let entries = try_null!(entry_manager.list(prev_uid.as_deref(), limit));
    let mut entries: Vec<*mut Entry> = entries.into_iter().map(|entry| {
        Box::into_raw(
            Box::new(entry)
        )
    }).collect();
    entries.push(std::ptr::null_mut());

    let ret = entries.as_mut_ptr();
    std::mem::forget(entries);

    ret
}

/// Creates entries specified in the list
#[no_mangle]
pub extern fn etesync_entry_manager_create(entry_manager: &EntryManager, entries: *const *const Entry, prev_uid: *const c_char) -> i32 {
    let prev_uid = unsafe {
        prev_uid.as_ref().and_then(|prev_uid| Some(CStr::from_ptr(prev_uid).to_string_lossy().to_string()))
    };
    let mut to_create: Vec<&Entry> = vec![];
    unsafe {
        for i in 0.. {
            if let Some(cur) = (*entries.offset(i)).as_ref() {
                to_create.push(&*cur);
            } else {
                break;
            }
        }
    }
    res_to_c_ret(entry_manager.create(&to_create, prev_uid.as_deref()))
}

/// Destroys the entry manager object
#[no_mangle]
pub extern fn etesync_entry_manager_destroy(entry_manager: &mut EntryManager) {
    let entry_manager = unsafe { Box::from_raw(entry_manager) };
    drop(entry_manager);
}

/// Returns encrypted entry from the sync entry
#[no_mangle]
pub extern fn etesync_entry_from_sync_entry(crypto_manager: &CryptoManager, sync_entry: &SyncEntry, prev_uid: *const c_char) -> *mut Entry {
    let prev_uid = unsafe {
        prev_uid.as_ref().and_then(|prev_uid| Some(CStr::from_ptr(prev_uid).to_string_lossy().to_string()))
    };

    let entry = try_null!(Entry::from_sync_entry(crypto_manager, sync_entry, prev_uid.as_deref()));

    Box::into_raw(
        Box::new(entry)
    )
}

/// Returns the entry uid
#[no_mangle]
pub extern fn etesync_entry_get_uid(entry: &Entry) -> *mut c_char {
    try_null!(CString::new(&entry.uid[..])).into_raw()
}

/// Decrypts the entry and returns the sync entry 
#[no_mangle]
pub extern fn etesync_entry_get_sync_entry(entry: &Entry, crypto_manager: &CryptoManager, prev_uid: *const c_char) -> *mut SyncEntry {
    let prev_uid = unsafe {
        prev_uid.as_ref().and_then(|prev_uid| Some(CStr::from_ptr(prev_uid).to_string_lossy().to_string()))
    };
    let sync_entry = try_null!(entry.get_sync_entry(&crypto_manager, prev_uid.as_deref()));

    Box::into_raw(
        Box::new(sync_entry)
    )
}

/// Returns a new sync entry
#[no_mangle]
pub extern fn etesync_sync_entry_new(action: *const c_char, content: *const c_char) -> *mut SyncEntry {
    let action = (unsafe { CStr::from_ptr(action) }).to_string_lossy().to_string();
    let content = (unsafe { CStr::from_ptr(content) }).to_string_lossy().to_string();

    let sync_entry = SyncEntry {
        action,
        content,
    };

    Box::into_raw(
        Box::new(sync_entry)
    )
}

/// Returns the sync entry action
#[no_mangle]
pub extern fn etesync_sync_entry_get_action(sync_entry: &SyncEntry) -> *mut c_char {
    try_null!(CString::new(&sync_entry.action[..])).into_raw()
}

/// Returns the sync entry content
#[no_mangle]
pub extern fn etesync_sync_entry_get_content(sync_entry: &SyncEntry) -> *mut c_char {
    try_null!(CString::new(&sync_entry.content[..])).into_raw()
}

/// Destroys the sync entry object
#[no_mangle]
pub extern fn etesync_sync_entry_destroy(sync_entry: &mut SyncEntry) {
    let sync_entry = unsafe { Box::from_raw(sync_entry) };
    drop(sync_entry);
}

/// Destroys the entry object
#[no_mangle]
pub extern fn etesync_entry_destroy(entry: &mut Entry) {
    let entry = unsafe { Box::from_raw(entry) };
    drop(entry);
}



/// Returns a new user info manager
#[no_mangle]
pub extern fn etesync_user_info_manager_new(etesync: &EteSync) -> *mut UserInfoManager {
    let user_info_manager = UserInfoManager::new(&etesync.client);

    Box::into_raw(
        Box::new(user_info_manager)
    )
}

/// Gets the user info
#[no_mangle]
pub extern fn etesync_user_info_manager_fetch(user_info_manager: &UserInfoManager, owner: *const c_char) -> *mut UserInfo {
    let owner = (unsafe { CStr::from_ptr(owner) }).to_string_lossy();
    let user_info = try_null!(user_info_manager.fetch(&owner));

    Box::into_raw(
        Box::new(user_info)
    )
}

/// Returns a new cypto manager for the user info
#[no_mangle]
pub extern fn etesync_user_info_get_crypto_manager(user_info: &UserInfo, key: *const c_char) -> *mut CryptoManager {
    let key = (unsafe { CStr::from_ptr(key) }).to_string_lossy();
    let key = try_null!(base64::decode(&key[..]));
    let crypto_manager = try_null!(user_info.get_crypto_manager(&key));

    Box::into_raw(
        Box::new(crypto_manager)
    )
}

/// Retrieves the keypair from the user info
#[no_mangle]
pub extern fn etesync_user_info_get_keypair(user_info: &UserInfo, crypto_manager: &CryptoManager) -> *mut AsymmetricKeyPair {
    let keypair = try_null!(user_info.get_keypair(&crypto_manager));

    Box::into_raw(
        Box::new(keypair)
    )
}

/// Sets keypair into the user info
#[no_mangle]
pub extern fn etesync_user_info_set_keypair(user_info: *mut UserInfo, crypto_manager: &CryptoManager, keypair: &AsymmetricKeyPair) -> i32 {
    let mut user_info = unsafe { Box::from_raw(user_info) };

    res_to_c_ret(user_info.set_keypair(&crypto_manager, &keypair))
}

/// Destroys the keypair object
#[no_mangle]
pub extern fn etesync_keypair_destroy(keypair: &mut AsymmetricKeyPair) {
    let keypair = unsafe { Box::from_raw(keypair) };
    drop(keypair);
}

/// Returns the user info version
#[no_mangle]
pub extern fn etesync_user_info_get_version(user_info: &UserInfo) -> u8 {
    user_info.version
}

/// Destroys the user info object
#[no_mangle]
pub extern fn etesync_user_info_destroy(user_info: *mut UserInfo) {
    let user_info = unsafe { Box::from_raw(user_info) };
    drop(user_info);
}

/// Destroys the user info manager object
#[no_mangle]
pub extern fn etesync_user_info_manager_destroy(user_info_manager: &mut UserInfoManager) {
    let user_info_manager = unsafe { Box::from_raw(user_info_manager) };
    drop(user_info_manager);
}
