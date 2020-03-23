use etesync::{
    service::{
        test_reset,
        get_client,
        Authenticator,
        JournalManager,
        Journal,
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

#[test]
fn simple_sync() {
    let client = get_client().unwrap();
    let authenticator = Authenticator::new(&client, TEST_API_URL);
    let token = authenticator.get_token(USER, PASSWORD).unwrap();
    test_reset(&client, &token, TEST_API_URL).unwrap();

    let journal_manager = JournalManager::new(&client, &token, TEST_API_URL);

    let mut journal = Journal {
        uid: String::from("f3436f50b2f7f1613ad142dbce1d24801d9daaabc45ecb2db909251a214c9841"),
        version: 2,
        owner: String::from(""),
        content: b"bla".to_vec(),
        read_only: false,
        key: None,
        last_uid: None,
    };

    {
        journal_manager.create(&journal).unwrap();
        let journal2 = journal_manager.fetch(&journal.uid).unwrap();

        assert_eq!(journal.content, journal2.content);
    }

    assert_eq!(journal_manager.list().unwrap().len(), 1);

    {
        journal.content = b"bla2".to_vec();

        journal_manager.update(&journal).unwrap();
        let journal2 = journal_manager.fetch(&journal.uid).unwrap();
        assert_eq!(journal.content, journal2.content);
    }

    {
        journal.uid = String::from("f3436f50b2f7f1613ad142dbce1d24801d9daaabc45ecb2db909251a20000000");
        journal.content = b"blabla".to_vec();

        journal_manager.create(&journal).unwrap();
        assert_eq!(journal_manager.list().unwrap().len(), 2);
    }

    journal_manager.delete(&journal).unwrap();

    assert_eq!(journal_manager.list().unwrap().len(), 1);

    authenticator.invalidate_token(&token).unwrap();
}
