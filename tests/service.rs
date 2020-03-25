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
    content::{
        ACTION_ADD,
        CollectionInfo,
        SyncEntry,
    }
};

mod common;

use common::{
    USER,
    PASSWORD,
    get_encryption_key,
};

const TEST_API_URL: &str = "http://localhost:8000";
const CLIENT_NAME: &str = "etesync-tests";

#[test]
fn auth_token() {
    let client = get_client(CLIENT_NAME).unwrap();
    let authenticator = Authenticator::new(&client, TEST_API_URL);
    let token = authenticator.get_token(USER, PASSWORD).unwrap();

    authenticator.invalidate_token(&token).unwrap();
}

#[test]
fn simple_sync() {
    let client = get_client(CLIENT_NAME).unwrap();
    let authenticator = Authenticator::new(&client, TEST_API_URL);
    let token = authenticator.get_token(USER, PASSWORD).unwrap();
    test_reset(&client, &token, TEST_API_URL).unwrap();

    let derived = get_encryption_key();
    let keypair = crypto::AsymmetricKeyPair::generate_keypair().unwrap();

    let journal_manager = JournalManager::new(&client, &token, TEST_API_URL);

    let mut journal = Journal::new(
        "f3436f50b2f7f1613ad142dbce1d24801d9daaabc45ecb2db909251a214c9841",
        crypto::CURRENT_VERSION,
        USER);

    let crypto_manager = journal.get_crypto_manager(&derived, &keypair).unwrap();

    let info = CollectionInfo {
        col_type: "CALENDAR".to_owned(),
        display_name: "Default".to_owned(),
        description: None,
        color: None,
    };

    journal.set_info(&crypto_manager, &info).unwrap();

    {
        let info2 = journal.get_info(&crypto_manager).unwrap();
        assert_eq!(&info2.display_name, &info.display_name);
    }

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

        let sync_entry = SyncEntry {
            action: ACTION_ADD.to_owned(),
            content: "bla1".to_owned(),
        };
        let entry = Entry::from_sync_entry(&crypto_manager, &sync_entry, None).unwrap();

        entry_manager.create(&[&entry], None).unwrap();
        assert_eq!(entry_manager.list(None, None).unwrap().len(), 1);

        let tmp = SyncEntry {
            action: ACTION_ADD.to_owned(),
            content: "bla2".to_owned(),
        };
        let entry2 = Entry::from_sync_entry(&crypto_manager, &tmp, Some(&entry.uid)).unwrap();

        let tmp = SyncEntry {
            action: ACTION_ADD.to_owned(),
            content: "bla3".to_owned(),
        };
        let entry3 = Entry::from_sync_entry(&crypto_manager, &tmp, Some(&entry2.uid)).unwrap();

        entry_manager.create(&[&entry2, &entry3], Some(&entry.uid)).unwrap();
        assert_eq!(entry_manager.list(None, None).unwrap().len(), 3);
        assert_eq!(entry_manager.list(Some(&entry.uid), None).unwrap().len(), 2);
        assert_eq!(entry_manager.list(Some(&entry.uid), Some(1)).unwrap().len(), 1);

        let entries = entry_manager.list(None, None).unwrap();
        let tmp = entries[0].get_sync_entry(&crypto_manager, None).unwrap();
        assert_eq!(&tmp.content, "bla1");
        let tmp = entries[1].get_sync_entry(&crypto_manager, Some(&entries[0].uid)).unwrap();
        assert_eq!(&tmp.content, "bla2");
        let tmp = entries[2].get_sync_entry(&crypto_manager, Some(&entries[1].uid)).unwrap();
        assert_eq!(&tmp.content, "bla3");
    }


    authenticator.invalidate_token(&token).unwrap();
}
