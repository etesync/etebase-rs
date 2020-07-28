package com.etebase.client.exceptions;

public class HttpException extends ConnectionException {
    public HttpException(String message) {
        super(message);
    }
}