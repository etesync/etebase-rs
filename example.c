// Compilation instructions:
// gcc example.c -o ./target/example -L. -l:target/debug/libetesync.so
// Running:
// ./target/example USERNAME PASSWORD ENCRYPTION_PASSWORD SERVER [COLLECTION_UID]

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "target/etesync.h"

void print_journal(const EteSyncJournal *journal, const EteSyncCollectionInfo *info) {
    char *uid = etesync_journal_get_uid(journal);
    int version = etesync_journal_get_version(journal);

    char *display_name = etesync_collection_info_get_display_name(info);

    printf("UID: %s (version: %d)\n", uid, version);
    printf("Display name: %s\n\n", display_name);

    free(display_name);
    free(uid);
}

void print_entry(const EteSyncEntry *entry, const EteSyncSyncEntry* sync_entry) {
    char *uid = etesync_entry_get_uid(entry);
    char *action = etesync_sync_entry_get_action(sync_entry);
    char *content = etesync_sync_entry_get_content(sync_entry);

    printf("UID: %s\n", uid);
    printf("Action: %s\n", action);
    printf("Content: %s\n", content);

    free(content);
    free(action);
    free(uid);
}

int main(int argc, char *argv[]) {
    const char *username = argv[1];
    const char *password = argv[2];
    const char *encryption_password = argv[3];
    const char *server_url = argv[4];
    EteSync *etesync = etesync_new("test.c", server_url);
    char *derived = etesync_crypto_derive_key(etesync, username, encryption_password);

    char *token = etesync_auth_get_token(etesync, username, password);

    etesync_set_auth_token(etesync, token);

    EteSyncJournalManager *journal_manager = etesync_journal_manager_new(etesync);
    printf("%s\n", etesync_get_server_url());

    EteSyncAsymmetricKeyPair *keypair = NULL;

    {
        EteSyncUserInfoManager *user_info_manager = etesync_user_info_manager_new(etesync);
        EteSyncUserInfo *user_info = etesync_user_info_manager_fetch(user_info_manager, username);
        EteSyncCryptoManager *user_info_crypto_manager = etesync_user_info_get_crypto_manager(user_info, derived);

        keypair = etesync_user_info_get_keypair(user_info, user_info_crypto_manager);

        etesync_crypto_manager_destroy(user_info_crypto_manager);
        etesync_user_info_destroy(user_info);
        etesync_user_info_manager_destroy(user_info_manager);
    }

    const char *journal_uid = argv[5];
    if (journal_uid) {
        EteSyncJournal *journal = etesync_journal_manager_fetch(journal_manager, journal_uid);

        EteSyncCryptoManager *crypto_manager = etesync_journal_get_crypto_manager(journal, derived, keypair);

        EteSyncCollectionInfo *info = etesync_journal_get_info(journal, crypto_manager);

        print_journal(journal, info);

        EteSyncEntryManager *entry_manager = etesync_entry_manager_new(etesync, journal_uid);

        int limit = 5;
        EteSyncEntry **entries = etesync_entry_manager_list(entry_manager, NULL, limit);
        printf("Printing the first %d entries:\n", limit);

        char *prev_uid = NULL;
        for (EteSyncEntry **iter = entries ; *iter ; iter++) {
            EteSyncEntry *entry = *iter;

            EteSyncSyncEntry *sync_entry = etesync_entry_get_sync_entry(entry, crypto_manager, prev_uid);

            print_entry(entry, sync_entry);

            free(prev_uid);
            prev_uid = etesync_entry_get_uid(entry);

            etesync_sync_entry_destroy(sync_entry);

            etesync_entry_destroy(entry);
        }

        free(prev_uid);

        free(entries);

        etesync_entry_manager_destroy(entry_manager);

        etesync_collection_info_destroy(info);
        etesync_crypto_manager_destroy(crypto_manager);
        etesync_journal_destroy(journal);
    } else {
        EteSyncJournal **journals = etesync_journal_manager_list(journal_manager);

        for (EteSyncJournal **iter = journals ; *iter ; iter++) {
            EteSyncJournal *journal = *iter;

            EteSyncCryptoManager *crypto_manager = etesync_journal_get_crypto_manager(journal, derived, keypair);

            EteSyncCollectionInfo *info = etesync_journal_get_info(journal, crypto_manager);

            print_journal(journal, info);

            etesync_collection_info_destroy(info);
            etesync_crypto_manager_destroy(crypto_manager);
            etesync_journal_destroy(journal);
        }

        free(journals);
    }

    etesync_keypair_destroy(keypair);

    etesync_journal_manager_destroy(journal_manager);

    etesync_auth_invalidate_token(etesync, token);

    free(token);
    free(derived);

    etesync_destroy(etesync);

    return 0;
}
