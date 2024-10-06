package com.sohoffice.security.authorization.io.v1;

import com.sohoffice.security.authorization.io.AuthEffect;
import com.sohoffice.security.authorization.io.AuthStatement;

import java.util.List;

public record AuthStatementV1(
        List<String> resources,
        List<String> principals,
        List<String> actions,
        AuthEffect effect,
        String identifier
) implements AuthStatement {
}
