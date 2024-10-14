package com.sohoffice.security.authorization.util;

import com.sohoffice.security.authorization.exceptions.NotFullyEnhancedException;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A combination of {@link StringExpression} and {@link StringMatchable}.
 * <p>
 * The input will first be enhanced with variables. Once fully enhanced it can be used to do matching.
 */
public class StringMatchableExpression implements Expression<StringMatchableExpression> {
  private final String original;

  private final StringExpression expression;
  private StringMatchable matchable;

  public StringMatchableExpression(String original) {
    this.original = original;
    this.expression = new StringExpression(original);
  }

  public StringMatchableExpression(String original, StringExpression expression) {
    this.original = original;
    this.expression = expression;
  }

  public StringMatchableExpression(String original, StringExpression expression, StringMatchable matchable) {
    this.original = original;
    this.expression = expression;
    this.matchable = matchable;
  }

  @Override
  public StringMatchableExpression enhance(Map.Entry<String, String> attribute) {
    return new StringMatchableExpression(original, expression.enhance(attribute));
  }

  @Override
  public Class<StringMatchableExpression> getExpressionType() {
    return StringMatchableExpression.class;
  }

  @Override
  public String getValue() {
    return expression.getValue();
  }

  @Override
  public boolean isFullyEnhanced() {
    return expression.isFullyEnhanced();
  }

  /**
   * Check if the string matches the given value.
   *
   * @param value String value to check
   * @return True if the string matches the given value.
   */
  public boolean matches(String value) {
    return matchable != null && matchable.matches(value);
  }

  public StringMatchableExpression toMatchable() {
    if (matchable != null) {
      return this;
    }
    if (isFullyEnhanced()) {
      return new StringMatchableExpression(original, expression, new StringMatchable(expression.getValue()));
    }
    throw new NotFullyEnhancedException(expression.getValue());
  }

  @Override
  public String toString() {
    return Stream.of("expression=" + expression, "matchable=" + matchable)
            .collect(Collectors.joining(", ", "SME{", "}"));
  }
}
