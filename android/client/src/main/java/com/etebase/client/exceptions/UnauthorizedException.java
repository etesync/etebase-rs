package com.etebase.client.exceptions;

public class UnauthorizedException extends HttpException {
    public UnauthorizedException(String message) {
        super(message);
    }
}