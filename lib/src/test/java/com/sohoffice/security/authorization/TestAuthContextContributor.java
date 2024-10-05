package com.sohoffice.security.authorization;

import java.util.Map;
import java.util.Set;

/**
 * Default implementation of {@link AuthContextContributor}.
 */
public class TestAuthContextContributor implements AuthContextContributor {
  private final String id;
  private final Set<Map.Entry<String, String>> attributes;

  public TestAuthContextContributor(String id, Map.Entry<String, String>... attrs) {
    this.id = id;
    this.attributes = Set.of(attrs);
  }

  @Override
  public Result contribute(AuthContext input) {
    return new Result(id, attributes);
  }
}
