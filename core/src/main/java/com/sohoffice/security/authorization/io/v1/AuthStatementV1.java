package com.sohoffice.security.authorization.io.v1;

import com.sohoffice.security.authorization.io.AuthEffect;
import com.sohoffice.security.authorization.io.AuthStatement;

import java.util.List;

public record AuthStatementV1(
        List<String> getResourcesList,
        List<String> getPrincipalsList,
        List<String> getActionsList,
        AuthEffect getEffect,
        String getIdentifier
) implements AuthStatement {
}
