package com.etebase.client.exceptions;

public class ConflictException extends HttpException {
    public ConflictException(String message) {
        super(message);
    }
}