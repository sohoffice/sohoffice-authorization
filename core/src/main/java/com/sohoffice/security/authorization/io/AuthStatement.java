package com.sohoffice.security.authorization.io;

import java.util.List;

/**
 * Describe one authorization rule.
 * <p>
 * The authorization is the combination of 3 components: resources, principals and actions. All 3 components  must
 * be matched to indicate this statement is applicable, where effect will indicate the result.
 * <p>
 * Within the same component, say for example resources, any match will be considered as a match.
 * If one of the components is empty, it means it is a wildcard and any value will match.
 */
public interface AuthStatement {
  List<String> getResourcesList();

  List<String> getPrincipalsList();

  List<String> getActionsList();

  AuthEffect getEffect();

  String getIdentifier();
}
