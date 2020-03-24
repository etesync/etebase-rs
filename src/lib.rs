extern crate openssl;
extern crate base64;

use std::os::raw::c_char;
use std::ffi::{CString, CStr};

use reqwest::blocking::Client;

pub mod crypto;
pub mod service;
pub mod content;

use self::{
    crypto::{
        derive_key,
        AsymmetricKeyPair,
    },
    service::{
        get_client,
        Authenticator,
        JournalManager,
        Journal,
        EntryManager,
        Entry,
    },
    content::{
        CollectionInfo,
        SyncEntry,
    }
};

#[no_mangle]
pub struct EteSync {
    client: Client,
    server_url: String,
}

#[no_mangle]
pub extern fn etesync_new(server_url: *const c_char) -> *mut EteSync {
    let server_url = (unsafe { CStr::from_ptr(server_url) }).to_string_lossy().into_owned();

    Box::into_raw(
        Box::new(EteSync {
            client: get_client().unwrap(),
            server_url,
        })
    )
}

#[no_mangle]
pub extern fn etesync_destroy(etesync: *mut EteSync) {
    let etesync = unsafe { Box::from_raw(etesync) };
    drop(etesync);
}


#[no_mangle]
pub extern fn etesync_crypto_derive_key(_etesync: *const EteSync, salt: *const c_char, password: *const c_char) -> *mut c_char {
    let salt = (unsafe { CStr::from_ptr(salt) }).to_string_lossy().into_owned();
    let password = (unsafe { CStr::from_ptr(password) }).to_string_lossy().into_owned();

    let derived = crypto::derive_key(&salt, &password).unwrap();

    let ret = CString::new(base64::encode(&derived)).unwrap();

    ret.into_raw()
}

#[no_mangle]
pub extern fn etesync_auth_get_token(etesync: *const EteSync, username: *const c_char, password: *const c_char) -> *mut c_char {
    let etesync = unsafe { &*etesync };
    let username = (unsafe { CStr::from_ptr(username) }).to_string_lossy().into_owned();
    let password = (unsafe { CStr::from_ptr(password) }).to_string_lossy().into_owned();

    let authenticator = Authenticator::new(&etesync.client, &etesync.server_url);
    let token = authenticator.get_token(&username, &password).unwrap();

    let ret = CString::new(&token[..]).unwrap();

    ret.into_raw()
}

#[no_mangle]
pub extern fn etesync_auth_invalidate_token(etesync: *const EteSync, token: *const c_char) -> bool {
    let etesync = unsafe { &*etesync };
    let token = (unsafe { CStr::from_ptr(token) }).to_string_lossy().into_owned();

    let authenticator = Authenticator::new(&etesync.client, &etesync.server_url);
    authenticator.invalidate_token(&token).unwrap();

    true
}

#[no_mangle]
pub extern fn etesync_journal_manager_new(etesync: *const EteSync, token: *const c_char) -> *mut JournalManager {
    let etesync = unsafe { &*etesync };
    let token = (unsafe { CStr::from_ptr(token) }).to_string_lossy().into_owned();
    let journal_manager = JournalManager::new(&etesync.client, &token, &etesync.server_url);

    Box::into_raw(
        Box::new(journal_manager)
    )
}

#[no_mangle]
pub extern fn etesync_journal_manager_destroy(journal_manager: *mut JournalManager) {
    let journal_manager = unsafe { Box::from_raw(journal_manager) };
    drop(journal_manager);
}

#[no_mangle]
pub extern fn etesync_journal_manager_fetch(journal_manager: *const JournalManager, journal_uid: *const c_char) -> *mut Journal {
    let journal_manager = unsafe { &*journal_manager };
    let journal_uid = (unsafe { CStr::from_ptr(journal_uid) }).to_string_lossy().into_owned();
    let journal = journal_manager.fetch(&journal_uid).unwrap();

    Box::into_raw(
        Box::new(journal)
    )
}

#[no_mangle]
pub extern fn etesync_journal_destroy(journal: *mut Journal) {
    let journal = unsafe { Box::from_raw(journal) };
    drop(journal);
}
