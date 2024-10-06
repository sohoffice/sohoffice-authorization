package com.sohoffice.security.authorization;

public record AuthRequestTarget(
        String resource,
        String action
) {
}
