package com.etebase.client.exceptions;

public class PermissionDeniedException extends HttpException {
    public PermissionDeniedException(String message) {
        super(message);
    }
}