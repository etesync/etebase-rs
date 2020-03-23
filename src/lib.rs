extern crate openssl;
extern crate base64;

use std::os::raw::c_char;
use std::ffi::{CString};

pub mod crypto;

#[no_mangle]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct EteSyncNetworkingFunctions {
    pub get: fn(etesync: *const EteSync, url: *const c_char) -> bool,
}

#[no_mangle]
pub struct EteSync {
    funcs: EteSyncNetworkingFunctions,
}

#[no_mangle]
pub extern fn etesync_init(funcs: &EteSyncNetworkingFunctions) -> *mut EteSync {
    Box::into_raw(
        Box::new(EteSync {
            funcs: funcs.clone(),
        })
    )
}

/*
#[no_mangle]
pub extern fn etesync_crypto_derive_key(etesync: *const EteSync, salt: *const c_char, password: *const c_char, retkey: *mut c_char) -> bool {
    let salt = (unsafe { CStr::from_ptr(salt) }).to_bytes();
    let password = (unsafe { CStr::from_ptr(password) }).to_bytes();
    let mut key: Box<[u8; 190]> = Box::new([0; 190]);
    // FIXME: we shouldn't be unwrapping!
    scrypt(password, salt, 16384, 8, 1, 0, &mut *key).unwrap();
    let base64key = base64::encode(key.as_ref());
    strcpy(retkey, base64key);
    true
}
*/

#[no_mangle]
pub extern fn etesync_dosomething(etesync: *const EteSync) {
    let etesync = unsafe { &*etesync };
    let c_string = CString::new(b"foo".to_vec()).expect("CString::new failed");
    let cstr = c_string.as_c_str();
    (etesync.funcs.get)(etesync, cstr.as_ptr());
}

#[no_mangle]
pub extern fn etesync_shutdown(etesync: *mut EteSync) {
    let etesync = unsafe { Box::from_raw(etesync) };
    drop(etesync);
}
