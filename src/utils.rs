use sodiumoxide::base64;

use super::error::{
    Error,
    Result,
};

pub fn from_base64(string: &str) -> Result<Vec<u8>> {
    match base64::decode(string, base64::Variant::UrlSafeNoPadding) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Err(Error::Base64("Failed decoding base64 string")),
    }
}

pub fn to_base64(bytes: &[u8]) -> Result<String> {
    Ok(base64::encode(bytes, base64::Variant::UrlSafeNoPadding))
}
