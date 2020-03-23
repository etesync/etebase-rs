use etesync::{
    service::{
        get_client,
        Authenticator,
    },
};

const TEST_API_URL: &str = "http://localhost:8000";

const USER: &str = "test@localhost";
const PASSWORD: &str = "SomePassword";

#[test]
fn auth_token() {
    let client = get_client().unwrap();
    let authenticator = Authenticator::new(&client, TEST_API_URL);
    let token = authenticator.get_token(USER, PASSWORD).unwrap();

    authenticator.invalidate_token(&token).unwrap();
}
