package com.sohoffice.security.authorization;

import java.util.Map;
import java.util.Set;

/**
 * An interface for application to contribute to the authorization context.
 */
public interface AuthContextContributor {

  Result contribute(AuthContext input);

  record Result(
          String contributorId,
          Set<Map.Entry<String, String>> attributes
  ) {
  }

}
