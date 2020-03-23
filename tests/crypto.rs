use etesync::crypto;

use base64;

const USER: &str = "test@localhost";
const PASSWORD: &str = "SomePassword";
const KEY_BASE64: &str = "Gpn6j6WJ/9JJbVkWhmEfZjlqSps5rwEOzjUOO0rqufvb4vtT4UfRgx0uMivuGwjF7/8Y1z1glIASX7Oz/4l2jucgf+lAzg2oTZFodWkXRZCDmFa7c9a8/04xIs7koFmUH34Rl9XXW6V2/GDVigQhQU8uWnrGo795tupoNQMbtB8RgMX5GyuxR55FvcybHpYBbwrDIsKvXcBxWFEscdNU8zyeq3yjvDo/W/y24dApW3mnNo7vswoL2rpkZj3dqw==";

#[test]
fn derive_key() {
    let derived = crypto::derive_key(USER, PASSWORD).unwrap();
    let derived64 = base64::encode(derived);
    assert_eq!(derived64, KEY_BASE64);
}
