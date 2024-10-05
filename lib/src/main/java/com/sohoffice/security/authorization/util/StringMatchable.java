package com.sohoffice.security.authorization.util;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A string that can be matched with a second string to a boolean original.
 * <p>
 * It matches if any of the following condition is true
 * 1. The two strings are equal
 * 2. This string has a wildcard character '*' and the second string matches the pattern
 * <p>
 * In the pattern, '*' matches any sequence of characters, except the below:
 * - empty string
 * - string with separator character, default to '/'
 */
public class StringMatchable {
  private final String value;
  private final boolean patterned;
  private final String replacement;
  private Pattern compiledPattern;
  public StringMatchable(String value) {
    this.value = value;
    this.patterned = value.contains("*");
    this.replacement = "[^/]+";
  }

  public StringMatchable(String value, String separator) {
    this.value = value;
    this.patterned = value.contains("*");
    this.replacement = "[^" + separator + "]+";
  }

  public boolean isPatterned() {
    return patterned;
  }

  public boolean matches(String target) {
    if (!patterned) {
      return Objects.equals(value, target);
    }
    if (compiledPattern == null) {
      compiledPattern = Pattern.compile(value.replace("*", replacement));
    }
    return compiledPattern.matcher(target).matches();
  }
}
