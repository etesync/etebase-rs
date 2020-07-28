package com.etebase.client;

import androidx.test.runner.AndroidJUnit4;

import com.etebase.client.exceptions.Base64Exception;

import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

import okhttp3.OkHttpClient;

import static java.nio.charset.StandardCharsets.UTF_8;

@RunWith(AndroidJUnit4.class)
public class Service {
    @Test
    public void testSmoketest() {
        OkHttpClient httpClient =  new OkHttpClient.Builder()
                // don't allow redirects by default, because it would break PROPFIND handling
                .followRedirects(false)
                .build();
        Client client = Client.create(httpClient, "http://10.100.102.5:12345");
        Account etebase = Account.login(client, "test_user", "SomePassword");
        CollectionManager col_mgr = etebase.getCollectionManager();
        CollectionMetadata collectionMetadata = new CollectionMetadata("Type", "Name");
        Collection col = col_mgr.create(collectionMetadata, "Something".getBytes());
        byte[] content = col.getContent();
        String str = new String(content, UTF_8);
        assertEquals(str, "Something");
        FetchOptions fetchOptions = new FetchOptions();
        fetchOptions.prefetch(true);
        col_mgr.upload(col, fetchOptions);
        CollectionListResponse col_list = col_mgr.list(null);
        assertNotEquals(col_list.getData().length, 0);
        fetchOptions = new FetchOptions();
        fetchOptions.stoken(col_list.getStoken().get());
        col_list = col_mgr.list(fetchOptions);
        assertEquals(col_list.getData().length, 0);

        Collection col2 = col_mgr.fetch(col.getUid(), null);
        byte[] content2 = col2.getContent();
        String str2 = new String(content2, UTF_8);
        assertEquals(str2, "Something");
        col2.setContent("Something else".getBytes());
        col_mgr.transaction(col2, null);

        ItemManager it_mgr = col_mgr.getItemManager(col);
        ItemMetadata itemMetadata = new ItemMetadata();
        itemMetadata.setItemType("Bla");
        Item item = it_mgr.create(itemMetadata, "Something item".getBytes());
        assertNotEquals(item.getUid(), "");
        assertNull(item.getEtag());
        byte[] it_content = item.getContent();
        String it_str = new String(it_content, UTF_8);
        assertEquals(it_str, "Something item");
        Item[] emptyArray = new Item[] {};
        it_mgr.batch(new Item[] {item}, null, null);
        assertNotNull(item.getEtag());
        item.setContent("Something item2".getBytes());
        it_mgr.transaction(new Item[] {item}, emptyArray, null);
        ItemListResponse item_list = it_mgr.list(null);
        assertEquals(item_list.getData().length, 1);
        Item it2_first = item_list.getData()[0];
        fetchOptions = new FetchOptions();
        fetchOptions.stoken(item_list.getStoken().get());
        item_list = it_mgr.list(fetchOptions);
        assertEquals(item_list.getData().length, 0);
        assertEquals(new String(it2_first.getContent(), UTF_8), "Something item2");

        etebase.logout();
    }

    @Test
    public void testCache() {
        OkHttpClient httpClient =  new OkHttpClient.Builder()
                // don't allow redirects by default, because it would break PROPFIND handling
                .followRedirects(false)
                .build();
        Client client = Client.create(httpClient,"http://10.100.102.5:12345");
        Account etebase = Account.login(client,"test_user","SomePassword");
        CollectionManager col_mgr = etebase.getCollectionManager();
        CollectionMetadata collectionMetadata = new CollectionMetadata("Type","Name");
        Collection col = col_mgr.create(collectionMetadata, "Something".getBytes());
        col_mgr.upload(col,null);

        String cached = etebase.save(null);
        etebase = Account.restore(client, cached,null);
        col_mgr = etebase.getCollectionManager();
        col = col_mgr.fetch(col.getUid(),null);
        assertArrayEquals(col.getContent(), "Something".getBytes());
        byte[] cachedCol = col_mgr.cacheSave(col);
        col = col_mgr.cacheLoad(cachedCol);
        assertEquals(col.getMeta().getCollectionType(), "Type");

        ItemManager it_mgr = col_mgr.getItemManager(col);
        ItemMetadata itemMetadata = new ItemMetadata();
        itemMetadata.setItemType("Bla");
        Item item = it_mgr.create(itemMetadata, "Something item".getBytes());
        it_mgr.batch(new Item[] {item}, null, null);
        byte[] cachedItem = it_mgr.cacheSaveWithContent(item);
        item = it_mgr.cacheLoad(cachedItem);
        assertArrayEquals(item.getContent(), "Something item".getBytes());

        etebase.logout();
    }

    @Test
    public void testBase64() {
        String encoded = Base64Url.toBase64("Test".getBytes());
        byte[] decoded = Base64Url.fromBase64(encoded);
        assertArrayEquals(decoded, "Test".getBytes());
    }

    @Test(expected=Base64Exception.class)
    public void base64Exception() {
        Base64Url.fromBase64("#@$@#$*@#$");
    }
}