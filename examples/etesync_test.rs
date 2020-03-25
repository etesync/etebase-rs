use std::env;

use etesync::{
    crypto::{
        derive_key,
        AsymmetricKeyPair,
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

const CLIENT_NAME: &str = "etesync-example";

fn print_journal(journal: &Journal, info: &CollectionInfo) {
    println!("UID: {} (version: {})", &journal.uid, journal.version);
    println!("Display name: {}", &info.display_name);
    println!();
}

fn print_entry(entry: &Entry, sync_entry: &SyncEntry) {
    println!("UID: {}", &entry.uid);
    println!("Action: {}", &sync_entry.action);
    println!("Content: {}", &sync_entry.content);
    println!();
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let username = &args[1];
    let password = &args[2];
    let enc_password = &args[3];
    let server_url = &args[4];

    let client = get_client(CLIENT_NAME).unwrap();
    let authenticator = Authenticator::new(&client, &server_url);
    let token = authenticator.get_token(&username, &password).unwrap();

    let derived = derive_key(&username, &enc_password).unwrap();
    let keypair = AsymmetricKeyPair::generate_keypair().unwrap();

    let journal_manager = JournalManager::new(&client, &token, &server_url);

    if args.len() >= 6 {
        let journal = journal_manager.fetch(&args[5]).unwrap();
        if journal.key == None {
            let entry_manager = EntryManager::new(&client, &token, &journal.uid, &server_url);

            let crypto_manager = journal.get_crypto_manager(&derived, &keypair).unwrap();
            let info = journal.get_info(&crypto_manager).unwrap();
            print_journal(&journal, &info);

            let limit = 5;
            let entries = entry_manager.list(None, Some(limit)).unwrap();
            println!("Printing the first {} entries:", limit);

            let mut prev_uid: Option<String> = None;
            for entry in entries {
                let sync_entry = entry.get_sync_entry(&crypto_manager, prev_uid.as_deref()).unwrap();
                print_entry(&entry, &sync_entry);
                prev_uid = Some(entry.uid.clone());
            }
        } else {
            println!("AsymmetricKeyPair journals are not currently supported.");
        }
    } else {
        for journal in journal_manager.list().unwrap() {
            if journal.key == None {
                let crypto_manager = journal.get_crypto_manager(&derived, &keypair).unwrap();
                let info = journal.get_info(&crypto_manager).unwrap();
                print_journal(&journal, &info);
            } else {
                println!("AsymmetricKeyPair journals are not currently supported.");
            }
        }
    }

    authenticator.invalidate_token(&token).unwrap();
}
