package com.sohoffice.security.authorization;

import java.util.Set;

/**
 * The application resource object that is being requested.
 *
 * @param resourceTargets The resource that is being requested.
 */
public record AuthRequest(
        Set<AuthRequestTarget> resourceTargets
) {
}
