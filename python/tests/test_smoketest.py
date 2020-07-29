import unittest
from .etebase import Client, Account, CollectionMetadata, ItemMetadata, FetchOptions


STORED_SESSION = "gqd2ZXJzaW9uAa1lbmNyeXB0ZWREYXRhxQGr_KWyDChQ6tXOJwJKf0Kw3QyR99itPIF3vZ5w6pVXSIq7AWul3fIXjIZOsBEwTVRumw7e9Af38D5oIL2VLNPLlmTOMjzIvuB00z3zDMFbH8pwrg2p_FvAhLHGjUGoXzU2XIxS4If7rQUfEz1zWkHPqWMrj4hACML5fks302dOUw7OsSMekcQaaVqMyj82MY3lG2qj8CL6ykSED7nW6OYWwMBJ1rSDGXhQRd5JuCGl6kgAHxKS6gkkIAWeUKjC6-Th2etk1XPKDiks0SZrQpmuXG8h_TBdd4igjRUqnIk09z5wvJFViXIU4M3pQomyFPk3Slh7KHvWhzxG0zbC2kUngQZ5h-LbVTLuT_TQWjYmHiOIihenrzl7z9MLebUq6vuwusZMRJ1Atau0Y2HcOzulYt4tLRP49d56qFEId3R4xomZ666hy-EFodsbzpxEKHeBUro3_gifOOKR8zkyLKTRz1UipZfKvnWk_RHFgZlSClRsXyaP34wstUavSiz-HNmTEmflNQKM7Awfel108FcSbW9NQAogW2Y2copP-P-R-DiHThrXmgDsWkTQFA"
SERVER_URL = "http://localhost:8033"


class TestStringMethods(unittest.TestCase):
    def test_main(self):
        client = Client.new("python_test", SERVER_URL)
        etebase = Account.restore(client, STORED_SESSION, None)
        etebase.force_api_base(SERVER_URL)
        etebase.fetch_token()

        col_mgr = etebase.get_collection_manager()
        col_meta = CollectionMetadata("Type", "Name")
        col = col_mgr.create(col_meta, b"Something")
        self.assertEqual(b"Something", bytes(col.get_content()))

        fetch_options = FetchOptions()
        fetch_options.prefetch(True)
        col_mgr.upload(col, fetch_options)

        col_list = col_mgr.list(None)
        self.assertNotEqual(0, len(col_list.get_data()))
        fetch_options = FetchOptions()
        fetch_options.stoken(col_list.get_stoken())
        col_list = col_mgr.list(fetch_options)
        self.assertEqual(0, len(col_list.get_data()))

        col2 = col_mgr.fetch(col.get_uid(), None)
        self.assertEqual(b"Something", bytes(col2.get_content()))
        col2.set_content(b"Something else")
        col_mgr.transaction(col2, None)

        it_mgr = col_mgr.get_item_manager(col)
        item_meta = ItemMetadata()
        item_meta.set_item_type("Bla")
        item = it_mgr.create(item_meta, b"Something item")
        self.assertNotEqual("", item.get_uid())
        self.assertIsNone(item.get_etag())
        self.assertEqual(b"Something item", bytes(item.get_content()))

        it_mgr.batch([item], None, None)
        etag1 = item.get_etag()
        self.assertIsNotNone(etag1)
        item.set_content(b"Something item2")

        it_mgr.transaction([item], None, None)
        self.assertNotEqual(item.get_etag(), etag1)

        item_list = it_mgr.list(None)
        self.assertEqual(1, len(item_list.get_data()))
        it_first = item_list.get_data()[0]
        self.assertEqual(b"Something item2", bytes(it_first.get_content()))

        fetch_options = FetchOptions()
        fetch_options.stoken(item_list.get_stoken())
        item_list = it_mgr.list(fetch_options)
        self.assertEqual(0, len(item_list.get_data()))

        etebase.logout()
