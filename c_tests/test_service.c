// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

#include "test_common.h"

const char *username = "test@localhost";
const char *password = "SomePassword";
const char *key64 = "Gpn6j6WJ/9JJbVkWhmEfZjlqSps5rwEOzjUOO0rqufvb4vtT4UfRgx0uMivuGwjF7/8Y1z1glIASX7Oz/4l2jucgf+lAzg2oTZFodWkXRZCDmFa7c9a8/04xIs7koFmUH34Rl9XXW6V2/GDVigQhQU8uWnrGo795tupoNQMbtB8RgMX5GyuxR55FvcybHpYBbwrDIsKvXcBxWFEscdNU8zyeq3yjvDo/W/y24dApW3mnNo7vswoL2rpkZj3dqw==";
const char *server_url = "http://localhost:8000";

int
test_auth_token() {
    EteSync *etesync = etesync_new("test_service", server_url);

    char *token = etesync_auth_get_token(etesync, username, password);

    etesync_auth_invalidate_token(etesync, token);

    free(token);

    etesync_destroy(etesync);

    return 0;
}

int
test_simple() {
    EteSync *etesync = etesync_new("test_service", server_url);

    char *token = etesync_auth_get_token(etesync, username, password);

    etesync_set_auth_token(etesync, token);


    etesync_test_reset(etesync);

    EteSyncAsymmetricKeyPair *keypair = etesync_crypto_generate_keypair(etesync);
    EteSyncJournalManager *journal_manager = etesync_journal_manager_new(etesync);

    char *uid = etesync_gen_uid();
    EteSyncJournal *journal = etesync_journal_new(uid, ETESYNC_CURRENT_VERSION);
    free(uid);

    EteSyncCryptoManager *crypto_manager = etesync_journal_get_crypto_manager(journal, key64, keypair);

    EteSyncCollectionInfo *info = etesync_collection_info_new("CALENDAR", "Default", NULL, ETESYNC_COLLECTION_DEFAULT_COLOR);

    etesync_journal_set_info(journal, crypto_manager, info);

    {
        EteSyncCollectionInfo *info2 = etesync_journal_get_info(journal, crypto_manager);

        char *display_name = etesync_collection_info_get_display_name(info2);
        assert_str_eq(display_name, "Default");
        free(display_name);

        etesync_collection_info_destroy(info2);
    }

    {
        int ret = etesync_journal_manager_create(journal_manager, journal);
        fail_if(ret);

        uid = etesync_journal_get_uid(journal);
        EteSyncJournal *journal2 = etesync_journal_manager_fetch(journal_manager, uid);

        fail_if(!journal2);

        etesync_journal_destroy(journal2);
        free(uid);


        EteSyncJournal **journals = etesync_journal_manager_list(journal_manager);

        int count = 0;
        for (EteSyncJournal **iter = journals ; *iter ; iter++) {
            EteSyncJournal *journal = *iter;

            count++;

            etesync_journal_destroy(journal);
        }
        assert_int_eq(count, 1);

        free(journals);
    }

    {
        char *uid = etesync_gen_uid();
        EteSyncJournal *journal2 = etesync_journal_new(uid, ETESYNC_CURRENT_VERSION);
        free(uid);

        EteSyncCryptoManager *crypto_manager = etesync_journal_get_crypto_manager(journal2, key64, keypair);
        etesync_journal_set_info(journal, crypto_manager, info);
        etesync_crypto_manager_destroy(crypto_manager);

        int ret = etesync_journal_manager_create(journal_manager, journal2);
        fail_if(ret);

        etesync_journal_destroy(journal2);

        EteSyncJournal **journals = etesync_journal_manager_list(journal_manager);

        int count = 0;
        for (EteSyncJournal **iter = journals ; *iter ; iter++) {
            EteSyncJournal *journal = *iter;

            count++;

            etesync_journal_destroy(journal);
        }
        assert_int_eq(count, 2);

        free(journals);
    }

    {
        char *journal_uid = etesync_journal_get_uid(journal);
        EteSyncEntryManager *entry_manager = etesync_entry_manager_new(etesync, journal_uid);

        EteSyncSyncEntry *sync_entry = etesync_sync_entry_new("ADD", "Test");
        char *prev_uid = NULL;
        EteSyncEntry *entry = etesync_entry_from_sync_entry(crypto_manager, sync_entry, prev_uid);

        EteSyncEntry const *entries[] = { entry, NULL };
        int ret = etesync_entry_manager_create(entry_manager, entries, prev_uid);

        fail_if(ret);

        char *push_uid = etesync_entry_get_uid(entry);
        prev_uid = push_uid;

        EteSyncEntry *entry2 = etesync_entry_from_sync_entry(crypto_manager, sync_entry, prev_uid);
        prev_uid = etesync_entry_get_uid(entry2);
        EteSyncEntry *entry3 = etesync_entry_from_sync_entry(crypto_manager, sync_entry, prev_uid);
        free(prev_uid);

        EteSyncEntry const *entries2[] = { entry2, entry3, NULL };
        ret = etesync_entry_manager_create(entry_manager, entries2, NULL);
        fail_if(!ret);
        assert_int_eq(etesync_get_error_code(), ETESYNC_ERROR_CODE_CONFLICT);

        ret = etesync_entry_manager_create(entry_manager, entries2, push_uid);
        fail_if(ret);

        etesync_entry_destroy(entry2);
        etesync_entry_destroy(entry3);

        EteSyncEntry **list_entries = etesync_entry_manager_list(entry_manager, NULL, 0);

        int count = 0;
        prev_uid = NULL;
        for (EteSyncEntry **iter = list_entries ; *iter ; iter++) {
            EteSyncEntry *entry = *iter;

            EteSyncSyncEntry *sync_entry = etesync_entry_get_sync_entry(entry, crypto_manager, prev_uid);

            free(prev_uid);
            prev_uid = etesync_entry_get_uid(entry);

            etesync_sync_entry_destroy(sync_entry);

            etesync_entry_destroy(entry);

            count++;
        }
        free(prev_uid);

        assert_int_eq(count, 3);

        free(list_entries);

        list_entries = etesync_entry_manager_list(entry_manager, NULL, 2);

        count = 0;
        prev_uid = NULL;
        for (EteSyncEntry **iter = list_entries ; *iter ; iter++) {
            EteSyncEntry *entry = *iter;

            EteSyncSyncEntry *sync_entry = etesync_entry_get_sync_entry(entry, crypto_manager, prev_uid);

            free(prev_uid);
            prev_uid = etesync_entry_get_uid(entry);

            etesync_sync_entry_destroy(sync_entry);

            etesync_entry_destroy(entry);

            count++;
        }
        free(prev_uid);

        assert_int_eq(count, 2);

        free(list_entries);

        list_entries = etesync_entry_manager_list(entry_manager, push_uid, 0);

        count = 0;
        prev_uid = strdup(push_uid);
        for (EteSyncEntry **iter = list_entries ; *iter ; iter++) {
            EteSyncEntry *entry = *iter;

            EteSyncSyncEntry *sync_entry = etesync_entry_get_sync_entry(entry, crypto_manager, prev_uid);

            free(prev_uid);
            prev_uid = etesync_entry_get_uid(entry);

            etesync_sync_entry_destroy(sync_entry);

            etesync_entry_destroy(entry);

            count++;
        }
        free(prev_uid);

        assert_int_eq(count, 2);

        free(list_entries);

        free(push_uid);
        etesync_sync_entry_destroy(sync_entry);
        etesync_entry_destroy(entry);
        etesync_entry_manager_destroy(entry_manager);
        free(journal_uid);
    }

    etesync_collection_info_destroy(info);

    etesync_journal_destroy(journal);

    etesync_crypto_manager_destroy(crypto_manager);
    etesync_journal_manager_destroy(journal_manager);
    etesync_keypair_destroy(keypair);
    etesync_auth_invalidate_token(etesync, token);
    free(token);
    etesync_destroy(etesync);

    return 0;
}

int
test_errors() {
    EteSync *etesync = etesync_new("test_service", "http://invalidhost");

    char *token = etesync_auth_get_token(etesync, username, password);
    fail_if(token);
    assert_int_eq(etesync_get_error_code(), ETESYNC_ERROR_CODE_CONNECTION);

    etesync_destroy(etesync);

    etesync = etesync_new("test_service", server_url);

    token = etesync_auth_get_token(etesync, "Bad username", password);
    fail_if(token);
    assert_int_eq(etesync_get_error_code(), ETESYNC_ERROR_CODE_HTTP);

    char *error_message = etesync_get_error_message();
    fail_if(!error_message);
    free(error_message);

    etesync_set_auth_token(etesync, "somebadtoken");
    EteSyncJournalManager *journal_manager = etesync_journal_manager_new(etesync);

    EteSyncJournal *journal = etesync_journal_manager_fetch(journal_manager, "whatever");
    fail_if(journal);
    assert_int_eq(etesync_get_error_code(), ETESYNC_ERROR_CODE_UNAUTHORIZED);

    etesync_journal_manager_destroy(journal_manager);

    etesync_destroy(etesync);


    etesync = etesync_new("test_service", server_url);

    token = etesync_auth_get_token(etesync, username, password);

    etesync_set_auth_token(etesync, token);

    EteSyncUserInfoManager *user_info_manager = etesync_user_info_manager_new(etesync);

    EteSyncUserInfo *user_info = etesync_user_info_manager_fetch(user_info_manager, "does_not_exist");
    fail_if(user_info);
    assert_int_eq(etesync_get_error_code(), ETESYNC_ERROR_CODE_NOT_FOUND);

    etesync_user_info_manager_destroy(user_info_manager);

    etesync_destroy(etesync);

    return 0;
}

int
test_user_info() {
    EteSync *etesync = etesync_new("test_service", server_url);

    char *token = etesync_auth_get_token(etesync, username, password);

    etesync_set_auth_token(etesync, token);

    etesync_test_reset(etesync);

    EteSyncAsymmetricKeyPair *keypair = etesync_crypto_generate_keypair(etesync);
    EteSyncUserInfo *user_info = etesync_user_info_new(username, ETESYNC_CURRENT_VERSION);
    fail_if(!user_info);
    EteSyncCryptoManager *crypto_manager = etesync_user_info_get_crypto_manager(user_info, key64);
    fail_if(etesync_user_info_set_keypair(user_info, crypto_manager, keypair));
    {
        EteSyncAsymmetricKeyPair *keypair = etesync_user_info_get_keypair(user_info, crypto_manager);
        fail_if(!keypair);
        etesync_keypair_destroy(keypair);
    }

    EteSyncUserInfoManager *user_info_manager = etesync_user_info_manager_new(etesync);

    fail_if(etesync_user_info_manager_create(user_info_manager, user_info));

    etesync_crypto_manager_destroy(crypto_manager);
    etesync_user_info_manager_destroy(user_info_manager);
    etesync_user_info_destroy(user_info);
    etesync_keypair_destroy(keypair);
    etesync_auth_invalidate_token(etesync, token);
    free(token);
    etesync_destroy(etesync);

    return 0;
}
