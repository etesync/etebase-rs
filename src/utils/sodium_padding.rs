extern crate libsodium_sys;

use libsodium_sys as ffi;

/// The `pad()` function adds padding data to a buffer buf whose original size is `unpadded_buflen`
/// in order to extend its total length to a multiple of blocksize.
///
/// The function returns `Err(())` if the padded buffer length would exceed `max_buflen`, or if the
/// block size is 0. It returns a result containing the new padded length upon success.
pub fn pad(buf: &mut [u8], unpadded_buflen: usize, blocksize: usize) -> Result<usize, ()> {
    let mut padded_buflen_p: usize = 0;
    unsafe {
        if 0 == ffi::sodium_pad(
            &mut padded_buflen_p,
            buf.as_mut_ptr() as *mut _,
            unpadded_buflen,
            blocksize,
            buf.len(),
        ) {
            Ok(padded_buflen_p)
        } else {
            Err(())
        }
    }
}

/// The `unpad()` function computes the original, unpadded length of a message previously padded
/// using [`pad()`]. The original length is returned upon success.
pub fn unpad(buf: &[u8], padded_buflen: usize, blocksize: usize) -> Result<usize, ()> {
    let mut unpadded_buflen_p: usize = 0;
    unsafe {
        if 0 == ffi::sodium_unpad(
            &mut unpadded_buflen_p,
            buf.as_ptr() as *const _,
            padded_buflen,
            blocksize,
        ) {
            Ok(unpadded_buflen_p)
        } else {
            Err(())
        }
    }
}
