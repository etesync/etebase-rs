extern crate openssl;
extern crate base64;

use std::os::raw::c_char;
use std::ffi::{CString, CStr};

use reqwest::blocking::Client;

use super::{
    crypto::{
        CURRENT_VERSION,
        derive_key,
        AsymmetricKeyPair,
        CryptoManager,
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
pub static ETESYNC_CURRENT_VERSION: u8 = CURRENT_VERSION;

#[no_mangle]
pub extern fn etesync_get_server_url() -> *const c_char {
    // FIXME: find a way to not clone SERVICE_API_URL,
    let service_url: *const u8 = b"https://api.etesync.com\0".as_ptr();
    return service_url as *const c_char;
}

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
    let salt = (unsafe { CStr::from_ptr(salt) }).to_string_lossy();
    let password = (unsafe { CStr::from_ptr(password) }).to_string_lossy();

    let derived = derive_key(&salt, &password).unwrap();

    let ret = CString::new(base64::encode(&derived)).unwrap();

    ret.into_raw()
}

#[no_mangle]
pub extern fn etesync_auth_get_token(etesync: *const EteSync, username: *const c_char, password: *const c_char) -> *mut c_char {
    let etesync = unsafe { &*etesync };
    let username = (unsafe { CStr::from_ptr(username) }).to_string_lossy();
    let password = (unsafe { CStr::from_ptr(password) }).to_string_lossy();

    let authenticator = Authenticator::new(&etesync.client, &etesync.server_url);
    let token = authenticator.get_token(&username, &password).unwrap();

    let ret = CString::new(&token[..]).unwrap();

    ret.into_raw()
}

#[no_mangle]
pub extern fn etesync_auth_invalidate_token(etesync: *const EteSync, token: *const c_char) -> bool {
    let etesync = unsafe { &*etesync };
    let token = (unsafe { CStr::from_ptr(token) }).to_string_lossy();

    let authenticator = Authenticator::new(&etesync.client, &etesync.server_url);
    authenticator.invalidate_token(&token).unwrap();

    true
}

#[no_mangle]
pub extern fn etesync_journal_manager_new(etesync: *const EteSync, token: *const c_char) -> *mut JournalManager {
    let etesync = unsafe { &*etesync };
    let token = (unsafe { CStr::from_ptr(token) }).to_string_lossy();
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
    let journal_uid = (unsafe { CStr::from_ptr(journal_uid) }).to_string_lossy();
    let journal = journal_manager.fetch(&journal_uid).unwrap();

    Box::into_raw(
        Box::new(journal)
    )
}

#[no_mangle]
pub extern fn etesync_journal_manager_list(journal_manager: *const JournalManager) -> *mut *mut Journal {
    let journal_manager = unsafe { &*journal_manager };
    let journals = journal_manager.list().unwrap();
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

#[no_mangle]
pub extern fn etesync_journal_get_uid(journal: *const Journal) -> *mut c_char {
    let journal = unsafe { &*journal };

    let ret = CString::new(&journal.uid[..]).unwrap();

    ret.into_raw()
}

#[no_mangle]
pub extern fn etesync_journal_get_version(journal: *const Journal) -> u8 {
    let journal = unsafe { &*journal };

    journal.version
}

#[no_mangle]
pub extern fn etesync_journal_get_owner(journal: *const Journal) -> *mut c_char {
    let journal = unsafe { &*journal };

    let ret = CString::new(&journal.owner[..]).unwrap();

    ret.into_raw()
}

#[no_mangle]
pub extern fn etesync_journal_is_read_only(journal: *const Journal) -> bool {
    let journal = unsafe { &*journal };

    journal.is_read_only()
}

#[no_mangle]
pub extern fn etesync_journal_get_last_uid(journal: *const Journal) -> *mut c_char {
    let journal = unsafe { &*journal };

    match journal.get_last_uid() {
        Some(last_uid) => {
            let ret = CString::new(&last_uid[..]).unwrap();

            ret.into_raw()
        },
        None => {
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern fn etesync_journal_get_info(journal: *const Journal, crypto_manager: *const CryptoManager) -> *mut CollectionInfo {
    let journal = unsafe { &*journal };
    let crypto_manager = unsafe { &*crypto_manager };
    let info = journal.get_info(&crypto_manager).unwrap();

    Box::into_raw(
        Box::new(info)
    )
}

#[no_mangle]
pub extern fn etesync_journal_get_crypto_manager(journal: *const Journal, key: *const c_char, keypair: *const AsymmetricKeyPair) -> *mut CryptoManager {
    let journal = unsafe { &*journal };
    let key = (unsafe { CStr::from_ptr(key) }).to_string_lossy();
    let key = base64::decode(&key[..]).unwrap();
    let keypair = unsafe { &*keypair };
    let crypto_manager = journal.get_crypto_manager(&key, &keypair).unwrap();

    Box::into_raw(
        Box::new(crypto_manager)
    )
}

#[no_mangle]
pub extern fn etesync_journal_destroy(journal: *mut Journal) {
    let journal = unsafe { Box::from_raw(journal) };
    drop(journal);
}

#[no_mangle]
pub extern fn etesync_crypto_manager_destroy(crypto_manager: *mut CryptoManager) {
    let crypto_manager = unsafe { Box::from_raw(crypto_manager) };
    drop(crypto_manager);
}

#[no_mangle]
pub extern fn etesync_collection_info_get_type(info: *const CollectionInfo) -> *mut c_char {
    let info = unsafe { &*info };

    let ret = CString::new(&info.col_type[..]).unwrap();

    ret.into_raw()
}

#[no_mangle]
pub extern fn etesync_collection_info_get_display_name(info: *const CollectionInfo) -> *mut c_char {
    let info = unsafe { &*info };

    let ret = CString::new(&info.display_name[..]).unwrap();

    ret.into_raw()
}

#[no_mangle]
pub extern fn etesync_collection_info_get_description(info: *const CollectionInfo) -> *mut c_char {
    let info = unsafe { &*info };

    match &info.description {
        Some(description) => {
            let ret = CString::new(&description[..]).unwrap();

            ret.into_raw()
        },
        None => {
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern fn etesync_collection_info_get_color(info: *const CollectionInfo) -> i32 {
    let info = unsafe { &*info };

    match info.color {
        Some(color) => color,
        None => -0x743cb6,
    }
}

#[no_mangle]
pub extern fn etesync_collection_info_destroy(info: *mut CollectionInfo) {
    let info = unsafe { Box::from_raw(info) };
    drop(info);
}



#[no_mangle]
pub extern fn etesync_entry_manager_new(etesync: *const EteSync, token: *const c_char, journal_uid: *const c_char) -> *mut EntryManager {
    let etesync = unsafe { &*etesync };
    let token = (unsafe { CStr::from_ptr(token) }).to_string_lossy();
    let journal_uid = (unsafe { CStr::from_ptr(journal_uid) }).to_string_lossy();
    let entry_manager = EntryManager::new(&etesync.client, &token, &journal_uid, &etesync.server_url);

    Box::into_raw(
        Box::new(entry_manager)
    )
}

#[no_mangle]
pub extern fn etesync_entry_manager_list(entry_manager: *const EntryManager, prev_uid: *const c_char, limit: usize) -> *mut *mut Entry {
    let entry_manager = unsafe { &*entry_manager };
    let prev_uid = if prev_uid == std::ptr::null() {
        None
    } else {
        Some((unsafe { CStr::from_ptr(prev_uid) }).to_string_lossy().to_string())
    };
    let limit = if limit == 0 {
        None
    } else {
        Some(limit)
    };

    let entries = entry_manager.list(prev_uid.as_deref(), limit).unwrap();
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

#[no_mangle]
pub extern fn etesync_entry_manager_destroy(entry_manager: *mut EntryManager) {
    let entry_manager = unsafe { Box::from_raw(entry_manager) };
    drop(entry_manager);
}

#[no_mangle]
pub extern fn etesync_entry_get_uid(entry: *const Entry) -> *mut c_char {
    let entry = unsafe { &*entry };

    let ret = CString::new(&entry.uid[..]).unwrap();

    ret.into_raw()
}

#[no_mangle]
pub extern fn etesync_entry_get_sync_entry(entry: *const Entry, crypto_manager: *const CryptoManager, prev_uid: *const c_char) -> *mut SyncEntry {
    let entry = unsafe { &*entry };
    let crypto_manager = unsafe { &*crypto_manager };
    let prev_uid = if prev_uid == std::ptr::null() {
        None
    } else {
        Some((unsafe { CStr::from_ptr(prev_uid) }).to_string_lossy().to_string())
    };
    let sync_entry = entry.get_sync_entry(&crypto_manager, prev_uid.as_deref()).unwrap();

    Box::into_raw(
        Box::new(sync_entry)
    )
}

#[no_mangle]
pub extern fn etesync_sync_entry_get_action(sync_entry: *const SyncEntry) -> *mut c_char {
    let sync_entry = unsafe { &*sync_entry };

    let ret = CString::new(&sync_entry.action[..]).unwrap();

    ret.into_raw()
}

#[no_mangle]
pub extern fn etesync_sync_entry_get_content(sync_entry: *const SyncEntry) -> *mut c_char {
    let sync_entry = unsafe { &*sync_entry };

    let ret = CString::new(&sync_entry.content[..]).unwrap();

    ret.into_raw()
}

#[no_mangle]
pub extern fn etesync_sync_entry_destroy(sync_entry: *mut SyncEntry) {
    let sync_entry = unsafe { Box::from_raw(sync_entry) };
    drop(sync_entry);
}

#[no_mangle]
pub extern fn etesync_entry_destroy(entry: *mut Entry) {
    let entry = unsafe { Box::from_raw(entry) };
    drop(entry);
}

