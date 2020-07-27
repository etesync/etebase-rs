package com.etebase.client;

import androidx.test.runner.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

import okhttp3.OkHttpClient;

import static java.nio.charset.StandardCharsets.UTF_8;

@RunWith(AndroidJUnit4.class)
public class Service {
    @Test
    public void testSmoketest () {
        OkHttpClient httpClient =  new OkHttpClient.Builder()
                // don't allow redirects by default, because it would break PROPFIND handling
                .followRedirects(false)
                .build();
        Client client = Client.create(httpClient, "http://10.100.102.5:12345");
        Account etebase = Account.login(client, "test_user", "SomePassword");
        CollectionManager col_mgr = etebase.getCollectionManager();
        Collection col = col_mgr.create("Something".getBytes());
        byte[] content = col.getContent();
        String str = new String(content, UTF_8);
        System.out.println(str);
        col_mgr.upload(col);
        CollectionListResponse col_list = col_mgr.list();
        System.out.printf("Stoken: %s%n", col_list.getStoken());
        System.out.printf("Count: %s%n", col_list.getData().length);
        Collection col2 = col_mgr.fetch(col.getUid());
        byte[] content2 = col2.getContent();
        String str2 = new String(content2, UTF_8);
        System.out.println(str2);
        col2.setContent("Something else".getBytes());
        col_mgr.transaction(col2);

        ItemManager it_mgr = col_mgr.getItemManager(col);
        Item item = it_mgr.create("Something item".getBytes());
        System.out.println(item.getUid());
        byte[] it_content = item.getContent();
        String it_str = new String(it_content, UTF_8);
        System.out.println(it_str);
        Item[] emptyArray = new Item[] {};
        it_mgr.batch(new Item[] {item}, emptyArray);
        item.setContent("Something item2".getBytes());
        it_mgr.transaction(new Item[] {item}, emptyArray);
        ItemListResponse item_list = it_mgr.list();
        System.out.printf("Stoken: %s%n", item_list.getStoken());
        Item it2_first = item_list.getData()[0];
        System.out.println(new String(it2_first.getContent(), UTF_8));

        etebase.logout();
    }
}