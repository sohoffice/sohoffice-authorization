package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.io.AuthStatement;
import com.sohoffice.security.authorization.util.Expression;
import com.sohoffice.security.authorization.util.Expressions;
import com.sohoffice.security.authorization.util.StringMatchableExpression;

import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * {@link AuthStatement} object in the process of evaluation.
 *
 * @param resources
 * @param principals
 * @param actions
 * @param statement
 */
public record AuthStatementToEvaluate(
        Set<StringMatchableExpression> resources,
        Set<StringMatchableExpression> principals,
        Set<StringMatchableExpression> actions,
        AuthStatement statement
) implements Expressions<AuthStatementToEvaluate> {
  @Override
  public AuthStatementToEvaluate enhance(Map.Entry<String, String> attribute) {
    return new AuthStatementToEvaluate(
            resources().stream()
                    .map(it -> it.enhance(attribute))
                    .collect(Collectors.toSet()),
            principals().stream()
                    .map(it -> it.enhance(attribute))
                    .collect(Collectors.toSet()),
            actions().stream()
                    .map(it -> it.enhance(attribute))
                    .collect(Collectors.toSet()),
            statement());
  }

  @Override
  public String getValue() {
    return resources.stream().map(Objects::toString).collect(Collectors.joining(",")) + ";" +
            principals().stream().map(Objects::toString).collect(Collectors.joining(",")) + ";" +
            actions().stream().map(Objects::toString).collect(Collectors.joining(","));
  }

  @Override
  public Class<AuthStatementToEvaluate> getExpressionType() {
    return AuthStatementToEvaluate.class;
  }

  @Override
  public boolean isFullyEnhanced() {
    return Stream.concat(Stream.concat(resources().stream(), principals().stream()), actions().stream())
            .filter(Predicate.not(StringMatchableExpression::isFullyEnhanced))
            .findAny()
            .isEmpty();
  }

  /**
   * @return Return True if any combination of principals, resources, and actions are fully enhanced.
   */
  @Override
  public boolean isPartiallyCompleted() {
    return principals().stream().anyMatch(Predicate.not(StringMatchableExpression::isFullyEnhanced)) &&
            resources().stream().anyMatch(Predicate.not(StringMatchableExpression::isFullyEnhanced)) &&
            actions().stream().anyMatch(Predicate.not(StringMatchableExpression::isFullyEnhanced));
  }

  /**
   * initialize {@link AuthStatementToEvaluate} from {@link AuthStatement}
   *
   * @return {@link AuthStatementToEvaluate}
   */
  public static AuthStatementToEvaluate ofAuthStatement(AuthStatement stmt) {
    return new AuthStatementToEvaluate(
            stmt.resources().stream()
                    .map(StringMatchableExpression::new)
                    .collect(Collectors.toSet()),
            stmt.principals().stream()
                    .map(StringMatchableExpression::new)
                    .collect(Collectors.toSet()),
            stmt.actions().stream()
                    .map(StringMatchableExpression::new)
                    .collect(Collectors.toSet()),
            stmt);
  }
}
