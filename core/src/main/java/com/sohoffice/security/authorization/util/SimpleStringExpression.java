package com.sohoffice.security.authorization.util;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A string that can be expanded with variables.
 */
class SimpleStringExpression {
  private final String value;
  private final boolean dynamic;

  public SimpleStringExpression(String value) {
    this.value = value;
    this.dynamic = value.contains("${");
  }

  public String getValue() {
    return value;
  }

  /**
   * Expand the string with the given variables.
   *
   * @param variables The variables to expand the string with.
   * @return The expanded string. Check {@link #isDynamic()} to see if the string is fully expanded.
   */
  public SimpleStringExpression withAttributes(Set<Map.Entry<String, String>> variables) {
    SimpleStringExpression cur = this;
    for (Map.Entry<String, String> variable : variables) {
      if (!cur.isDynamic()) {
        return cur;
      }
      cur = cur.withAttribute(variable);
    }
    return cur;
  }

  public SimpleStringExpression withAttribute(Map.Entry<String, String> attribute) {
    String exp = expand(attribute.getKey(), attribute.getValue());
    if (Objects.equals(exp, value)) {
      return this;
    }
    return new SimpleStringExpression(exp);
  }

  protected String expand(String k, String v) {
    if (!dynamic) {
      return value;
    }

    StringBuilder sb = new StringBuilder();
    int start = 0;
    int end = 0;
    while (end < value.length()) {
      start = value.indexOf("${", end);
      if (start == -1) {
        sb.append(value, end, value.length());
        break;
      }
      sb.append(value, end, start);
      end = value.indexOf("}", start);
      if (end == -1) {
        sb.append(value, start, value.length());
        break;
      }
      String variable = value.substring(start + 2, end);
      String replacement = (Objects.equals(variable, k)) ? v : null;
      if (replacement == null) {
        sb.append(value, start, end + 1);
      } else {
        sb.append(replacement);
      }
      end++;
    }
    return sb.toString();
  }

  protected boolean isDynamic() {
    return dynamic;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    SimpleStringExpression that = (SimpleStringExpression) o;
    return Objects.equals(value, that.value);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(value);
  }

  @Override
  public String toString() {
    return this.value;
  }
}
