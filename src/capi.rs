extern crate openssl;
extern crate base64;

use std::os::raw::c_char;
use std::ffi::{CString, CStr};

use reqwest::blocking::Client;

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
        get_client,
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
    }
};

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
    server_url: String,
}

#[no_mangle]
pub extern fn etesync_new(client_name: *const c_char, server_url: *const c_char) -> *mut EteSync {
    let server_url = (unsafe { CStr::from_ptr(server_url) }).to_string_lossy().into_owned();
    let client_name = (unsafe { CStr::from_ptr(client_name) }).to_string_lossy();

    Box::into_raw(
        Box::new(EteSync {
            client: get_client(&client_name).unwrap(),
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
pub extern fn etesync_test_reset(etesync: *const EteSync, token: *const c_char) -> i32 {
    let etesync = unsafe { &*etesync };
    let token = (unsafe { CStr::from_ptr(token) }).to_string_lossy();

    test_reset(&etesync.client, &token, &etesync.server_url).unwrap();

    0
}


#[no_mangle]
pub extern fn etesync_crypto_derive_key(_etesync: *const EteSync, salt: *const c_char, password: *const c_char) -> *mut c_char {
    let salt = (unsafe { CStr::from_ptr(salt) }).to_string_lossy();
    let password = (unsafe { CStr::from_ptr(password) }).to_string_lossy();

    let derived = derive_key(&salt, &password).unwrap();

    CString::new(base64::encode(&derived)).unwrap().into_raw()
}

#[no_mangle]
pub extern fn etesync_gen_uid() -> *mut c_char {
    CString::new(gen_uid().unwrap()).unwrap().into_raw()
}

#[no_mangle]
pub extern fn etesync_crypto_generate_keypair(_etesync: *const EteSync) -> *mut AsymmetricKeyPair {
    let keypair = AsymmetricKeyPair::generate_keypair().unwrap();

    Box::into_raw(
        Box::new(keypair)
    )
}

#[no_mangle]
pub extern fn etesync_auth_get_token(etesync: *const EteSync, username: *const c_char, password: *const c_char) -> *mut c_char {
    let etesync = unsafe { &*etesync };
    let username = (unsafe { CStr::from_ptr(username) }).to_string_lossy();
    let password = (unsafe { CStr::from_ptr(password) }).to_string_lossy();

    let authenticator = Authenticator::new(&etesync.client, &etesync.server_url);
    let token = authenticator.get_token(&username, &password).unwrap();

    CString::new(&token[..]).unwrap().into_raw()
}

#[no_mangle]
pub extern fn etesync_auth_invalidate_token(etesync: *const EteSync, token: *const c_char) -> i32 {
    let etesync = unsafe { &*etesync };
    let token = (unsafe { CStr::from_ptr(token) }).to_string_lossy();

    let authenticator = Authenticator::new(&etesync.client, &etesync.server_url);
    authenticator.invalidate_token(&token).unwrap();

    0
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
pub extern fn etesync_journal_manager_create(journal_manager: *const JournalManager, journal: *const Journal) -> i32 {
    let journal_manager = unsafe { &*journal_manager };
    let journal = unsafe { &*journal };
    journal_manager.create(&journal).unwrap();

    0
}

#[no_mangle]
pub extern fn etesync_journal_manager_update(journal_manager: *const JournalManager, journal: *const Journal) -> i32 {
    let journal_manager = unsafe { &*journal_manager };
    let journal = unsafe { &*journal };
    journal_manager.update(&journal).unwrap();

    0
}

#[no_mangle]
pub extern fn etesync_journal_manager_delete(journal_manager: *const JournalManager, journal: *const Journal) -> i32 {
    let journal_manager = unsafe { &*journal_manager };
    let journal = unsafe { &*journal };
    journal_manager.delete(&journal).unwrap();

    0
}

#[no_mangle]
pub extern fn etesync_journal_new(uid: *const c_char, version: u8) -> *mut Journal {
    let uid = (unsafe { CStr::from_ptr(uid) }).to_string_lossy();
    let journal = Journal::new(&uid[..], version);

    Box::into_raw(
        Box::new(journal)
    )
}

#[no_mangle]
pub extern fn etesync_journal_get_uid(journal: *const Journal) -> *mut c_char {
    let journal = unsafe { &*journal };

    CString::new(&journal.uid[..]).unwrap().into_raw()
}

#[no_mangle]
pub extern fn etesync_journal_get_version(journal: *const Journal) -> u8 {
    let journal = unsafe { &*journal };

    journal.version
}

#[no_mangle]
pub extern fn etesync_journal_get_owner(journal: *const Journal) -> *mut c_char {
    let journal = unsafe { &*journal };

    journal.owner.as_ref().and_then(|owner| {
        Some(CString::new(&owner[..]).unwrap().into_raw())
    }).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern fn etesync_journal_is_read_only(journal: *const Journal) -> bool {
    let journal = unsafe { &*journal };

    journal.is_read_only()
}

#[no_mangle]
pub extern fn etesync_journal_get_last_uid(journal: *const Journal) -> *mut c_char {
    let journal = unsafe { &*journal };

    journal.get_last_uid().as_ref().and_then(|last_uid| {
        Some(CString::new(&last_uid[..]).unwrap().into_raw())
    }).unwrap_or(std::ptr::null_mut())
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
pub extern fn etesync_journal_set_info(journal: *mut Journal, crypto_manager: *const CryptoManager, info: *const CollectionInfo) -> i32 {
    let mut journal = unsafe { Box::from_raw(journal) };
    let crypto_manager = unsafe { &*crypto_manager };
    let info = unsafe { &*info };

    journal.set_info(&crypto_manager, &info).unwrap();

    std::mem::forget(journal); // We don't want it freed

    0
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

#[no_mangle]
pub extern fn etesync_collection_info_get_type(info: *const CollectionInfo) -> *mut c_char {
    let info = unsafe { &*info };

    CString::new(&info.col_type[..]).unwrap().into_raw()
}

#[no_mangle]
pub extern fn etesync_collection_info_get_display_name(info: *const CollectionInfo) -> *mut c_char {
    let info = unsafe { &*info };

    CString::new(&info.display_name[..]).unwrap().into_raw()
}

#[no_mangle]
pub extern fn etesync_collection_info_get_description(info: *const CollectionInfo) -> *mut c_char {
    let info = unsafe { &*info };

    info.description.as_ref().and_then(|description| {
        Some(CString::new(&description[..]).unwrap().into_raw())
    }).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern fn etesync_collection_info_get_color(info: *const CollectionInfo) -> i32 {
    let info = unsafe { &*info };

    info.color.unwrap_or(DEFAULT_COLOR)
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
    let prev_uid = unsafe {
        prev_uid.as_ref().and_then(|prev_uid| Some(CStr::from_ptr(prev_uid).to_string_lossy().to_string()))
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
pub extern fn etesync_entry_manager_create(entry_manager: *const EntryManager, entries: *const *const Entry, prev_uid: *const c_char) -> i32 {
    let entry_manager = unsafe { &*entry_manager };
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
    entry_manager.create(&to_create, prev_uid.as_deref()).unwrap();

    0
}

#[no_mangle]
pub extern fn etesync_entry_manager_destroy(entry_manager: *mut EntryManager) {
    let entry_manager = unsafe { Box::from_raw(entry_manager) };
    drop(entry_manager);
}

#[no_mangle]
pub extern fn etesync_entry_from_sync_entry(crypto_manager: *const CryptoManager, sync_entry: *const SyncEntry, prev_uid: *const c_char) -> *mut Entry {
    let crypto_manager = unsafe { &*crypto_manager };
    let sync_entry = unsafe { &*sync_entry };
    let prev_uid = unsafe {
        prev_uid.as_ref().and_then(|prev_uid| Some(CStr::from_ptr(prev_uid).to_string_lossy().to_string()))
    };

    let entry = Entry::from_sync_entry(crypto_manager, sync_entry, prev_uid.as_deref()).unwrap();

    Box::into_raw(
        Box::new(entry)
    )
}

#[no_mangle]
pub extern fn etesync_entry_get_uid(entry: *const Entry) -> *mut c_char {
    let entry = unsafe { &*entry };

    CString::new(&entry.uid[..]).unwrap().into_raw()
}

#[no_mangle]
pub extern fn etesync_entry_get_sync_entry(entry: *const Entry, crypto_manager: *const CryptoManager, prev_uid: *const c_char) -> *mut SyncEntry {
    let entry = unsafe { &*entry };
    let crypto_manager = unsafe { &*crypto_manager };
    let prev_uid = unsafe {
        prev_uid.as_ref().and_then(|prev_uid| Some(CStr::from_ptr(prev_uid).to_string_lossy().to_string()))
    };
    let sync_entry = entry.get_sync_entry(&crypto_manager, prev_uid.as_deref()).unwrap();

    Box::into_raw(
        Box::new(sync_entry)
    )
}

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

#[no_mangle]
pub extern fn etesync_sync_entry_get_action(sync_entry: *const SyncEntry) -> *mut c_char {
    let sync_entry = unsafe { &*sync_entry };

    CString::new(&sync_entry.action[..]).unwrap().into_raw()
}

#[no_mangle]
pub extern fn etesync_sync_entry_get_content(sync_entry: *const SyncEntry) -> *mut c_char {
    let sync_entry = unsafe { &*sync_entry };

    CString::new(&sync_entry.content[..]).unwrap().into_raw()
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




#[no_mangle]
pub extern fn etesync_user_info_manager_new(etesync: *const EteSync, token: *const c_char) -> *mut UserInfoManager {
    let etesync = unsafe { &*etesync };
    let token = (unsafe { CStr::from_ptr(token) }).to_string_lossy();
    let user_info_manager = UserInfoManager::new(&etesync.client, &token, &etesync.server_url);

    Box::into_raw(
        Box::new(user_info_manager)
    )
}

#[no_mangle]
pub extern fn etesync_user_info_manager_fetch(user_info_manager: *const UserInfoManager, owner: *const c_char) -> *mut UserInfo {
    let user_info_manager = unsafe { &*user_info_manager };
    let owner = (unsafe { CStr::from_ptr(owner) }).to_string_lossy();
    let user_info = user_info_manager.fetch(&owner).unwrap();

    Box::into_raw(
        Box::new(user_info)
    )
}

#[no_mangle]
pub extern fn etesync_user_info_get_crypto_manager(user_info: *const UserInfo, key: *const c_char) -> *mut CryptoManager {
    let user_info = unsafe { &*user_info };
    let key = (unsafe { CStr::from_ptr(key) }).to_string_lossy();
    let key = base64::decode(&key[..]).unwrap();
    let crypto_manager = user_info.get_crypto_manager(&key).unwrap();

    Box::into_raw(
        Box::new(crypto_manager)
    )
}

#[no_mangle]
pub extern fn etesync_user_info_get_keypair(user_info: *const UserInfo, crypto_manager: *const CryptoManager) -> *mut AsymmetricKeyPair {
    let user_info = unsafe { &*user_info };
    let crypto_manager = unsafe { &*crypto_manager };

    let keypair = user_info.get_keypair(&crypto_manager).unwrap();

    Box::into_raw(
        Box::new(keypair)
    )
}

#[no_mangle]
pub extern fn etesync_user_info_set_keypair(user_info: *mut UserInfo, crypto_manager: *const CryptoManager, keypair: *const AsymmetricKeyPair) -> i32 {
    let mut user_info = unsafe { Box::from_raw(user_info) };
    let crypto_manager = unsafe { &*crypto_manager };
    let keypair = unsafe { &*keypair };

    user_info.set_keypair(&crypto_manager, &keypair).unwrap();

    std::mem::forget(user_info); // We don't want it freed

    0
}

#[no_mangle]
pub extern fn etesync_keypair_destroy(keypair: *mut AsymmetricKeyPair) {
    let keypair = unsafe { Box::from_raw(keypair) };
    drop(keypair);
}

#[no_mangle]
pub extern fn etesync_user_info_get_version(user_info: *const UserInfo) -> u8 {
    let user_info = unsafe { &*user_info };

    user_info.version
}

#[no_mangle]
pub extern fn etesync_user_info_destroy(user_info: *mut UserInfo) {
    let user_info = unsafe { Box::from_raw(user_info) };
    drop(user_info);
}

#[no_mangle]
pub extern fn etesync_user_info_manager_destroy(user_info_manager: *mut UserInfoManager) {
    let user_info_manager = unsafe { Box::from_raw(user_info_manager) };
    drop(user_info_manager);
}
