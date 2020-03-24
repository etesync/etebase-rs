use etesync::{
    crypto,
    service::{
        test_reset,
        get_client,
        Authenticator,
        JournalManager,
        Journal,
        EntryManager,
        Entry,
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

    let mut journal = Journal::new(
        "f3436f50b2f7f1613ad142dbce1d24801d9daaabc45ecb2db909251a214c9841",
        crypto::CURRENT_VERSION,
        USER);

    journal.content = b"bla".to_vec();

    {
        journal_manager.create(&journal).unwrap();
        let journal2 = journal_manager.fetch(&journal.uid).unwrap();

        assert_eq!(journal.content, journal2.content);
    }

    assert_eq!(journal_manager.list().unwrap().len(), 1);

    {
        let mut journal = journal.clone();
        journal.content = b"bla2".to_vec();

        journal_manager.update(&journal).unwrap();
        let journal2 = journal_manager.fetch(&journal.uid).unwrap();
        assert_eq!(journal.content, journal2.content);
    }

    {
        let mut journal = journal.clone();
        journal.uid = String::from("f3436f50b2f7f1613ad142dbce1d24801d9daaabc45ecb2db909251a20000000");
        journal.content = b"blabla".to_vec();

        journal_manager.create(&journal).unwrap();
        assert_eq!(journal_manager.list().unwrap().len(), 2);

        journal_manager.delete(&journal).unwrap();

        assert_eq!(journal_manager.list().unwrap().len(), 1);
    }

    {
        let entry_manager = EntryManager::new(&client, &token, &journal.uid, TEST_API_URL);

        let entry = Entry {
            uid: String::from("eeeeef50b2f7f1613ad142dbce1d24801d9daaabc45ecb2db909251a20000001"),
            content: b"bla".to_vec(),
        };

        entry_manager.create(&[&entry], None).unwrap();
        assert_eq!(entry_manager.list(None, None).unwrap().len(), 1);

        let entry2 = Entry {
            uid: String::from("eeeeef50b2f7f1613ad142dbce1d24801d9daaabc45ecb2db909251a20000002"),
            content: b"bla2".to_vec(),
        };

        let entry3 = Entry {
            uid: String::from("eeeeef50b2f7f1613ad142dbce1d24801d9daaabc45ecb2db909251a20000003"),
            content: b"bla3".to_vec(),
        };

        entry_manager.create(&[&entry2, &entry3], Some(&entry.uid)).unwrap();
        assert_eq!(entry_manager.list(None, None).unwrap().len(), 3);
        assert_eq!(entry_manager.list(Some(&entry.uid), None).unwrap().len(), 2);
        assert_eq!(entry_manager.list(Some(&entry.uid), Some(1)).unwrap().len(), 1);
    }


    authenticator.invalidate_token(&token).unwrap();
}
