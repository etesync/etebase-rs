package com.etebase.client.http_bridge;

import com.etebase.client.Client;
import com.etebase.client.HttpClient;
import com.etebase.client.Response;

import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.RequestBody;

public class HttpClientBridge implements HttpClient {
    protected OkHttpClient client = null;

    private final String HEADER_AUTHORIZATION = "Authorization";

    static MediaType MSGPACK = MediaType.parse("application/msgpack");

    private HttpClientBridge(OkHttpClient client) {
        this.client = client;
    }

    public static Client create(OkHttpClient client, String server_url) {
        return Client.client_new_with_impl(server_url, new HttpClientBridge(client));
    }

    public void get(String url, String auth_token, Response response) {
        try {
            HttpUrl httpUrl = HttpUrl.parse(url);
            okhttp3.Request.Builder req = new okhttp3.Request.Builder()
                    .header("ACCEPT", "application/msgpack")
                    .get()
                    .url(httpUrl);
            if (auth_token != null) {
                req = req.header(HEADER_AUTHORIZATION, "Token " + auth_token);
            }
            okhttp3.Response resp = client.newCall(req.build()).execute();
            response.reset_ok(resp.body().bytes(), resp.code());
        } catch (Exception e){
            response.reset_err(e.toString());
        }
    }

    public void post(String url, String auth_token, byte [] body, Response response) {
        try {
            HttpUrl httpUrl = HttpUrl.parse(url);
            RequestBody requestBody = RequestBody.create(MSGPACK, body);
            okhttp3.Request.Builder req = new okhttp3.Request.Builder()
                    .header("ACCEPT", "application/msgpack")
                    .post(requestBody)
                    .url(httpUrl);
            if (auth_token != null) {
                req = req.header(HEADER_AUTHORIZATION, "Token " + auth_token);
            }
            okhttp3.Response resp = client.newCall(req.build()).execute();
            response.reset_ok(resp.body().bytes(), resp.code());
        } catch (Exception e){
            response.reset_err(e.toString());
        }
    }


    public void put(String url, String auth_token, byte [] body, Response response) {
        try {
            HttpUrl httpUrl = HttpUrl.parse(url);
            RequestBody requestBody = RequestBody.create(MSGPACK, body);
            okhttp3.Request.Builder req = new okhttp3.Request.Builder()
                    .header("ACCEPT", "application/msgpack")
                    .put(requestBody)
                    .url(httpUrl);
            if (auth_token != null) {
                req = req.header(HEADER_AUTHORIZATION, "Token " + auth_token);
            }
            okhttp3.Response resp = client.newCall(req.build()).execute();
            response.reset_ok(resp.body().bytes(), resp.code());
        } catch (Exception e){
            response.reset_err(e.toString());
        }
    }


    public void patch(String url, String auth_token, byte [] body, Response response) {
        try {
            HttpUrl httpUrl = HttpUrl.parse(url);
            RequestBody requestBody = RequestBody.create(MSGPACK, body);
            okhttp3.Request.Builder req = new okhttp3.Request.Builder()
                    .header("ACCEPT", "application/msgpack")
                    .patch(requestBody)
                    .url(httpUrl);
            if (auth_token != null) {
                req = req.header(HEADER_AUTHORIZATION, "Token " + auth_token);
            }
            okhttp3.Response resp = client.newCall(req.build()).execute();
            response.reset_ok(resp.body().bytes(), resp.code());
        } catch (Exception e){
            response.reset_err(e.toString());
        }
    }


    public void del(String url, String auth_token, Response response) {
        try {
            HttpUrl httpUrl = HttpUrl.parse(url);
            okhttp3.Request.Builder req = new okhttp3.Request.Builder()
                    .header("ACCEPT", "application/msgpack")
                    .delete()
                    .url(httpUrl);
            if (auth_token != null) {
                req = req.header(HEADER_AUTHORIZATION, "Token " + auth_token);
            }
            okhttp3.Response resp = client.newCall(req.build()).execute();
            response.reset_ok(resp.body().bytes(), resp.code());
        } catch (Exception e){
            response.reset_err(e.toString());
        }
    }
}
