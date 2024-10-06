package com.sohoffice.security.authorization.exceptions;

public class SohofficeAuthException extends RuntimeException {
    public SohofficeAuthException(String message) {
        super(message);
    }

    public SohofficeAuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
