package com.sohoffice.security.authorization.io;

import java.util.List;

public record AuthDocument(
        String version,
        List<? extends AuthStatement> statements) {
}
