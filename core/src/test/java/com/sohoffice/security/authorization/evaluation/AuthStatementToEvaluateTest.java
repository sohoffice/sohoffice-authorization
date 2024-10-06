package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.util.StringMatchableExpression;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthStatementToEvaluateTest {

  @Test
  void isFullyEnhanced_GivenFullyEnhanced() {
    AuthStatementToEvaluate underTest = new AuthStatementToEvaluate(
            Set.of(new StringMatchableExpression("resources/foo")),
            Set.of(new StringMatchableExpression("principals/bar")),
            Set.of(new StringMatchableExpression("actions/baz")),
            null);
    assertTrue(underTest.isFullyEnhanced());
  }

  @Test
  void isFullyEnhanced_Given_Mixed() {
    AuthStatementToEvaluate underTest1 = new AuthStatementToEvaluate(
            Set.of(new StringMatchableExpression("resources/foo"), new StringMatchableExpression("dynamic/${name}")),
            Set.of(new StringMatchableExpression("principals/bar")),
            Set.of(new StringMatchableExpression("actions/baz")),
            null);
    assertFalse(underTest1.isFullyEnhanced());

    AuthStatementToEvaluate underTest2 = new AuthStatementToEvaluate(
            Set.of(new StringMatchableExpression("resources/foo")),
            Set.of(new StringMatchableExpression("dynamic/${name}"), new StringMatchableExpression("principals/bar")),
            Set.of(new StringMatchableExpression("actions/baz")),
            null);
    assertFalse(underTest2.isFullyEnhanced());

    AuthStatementToEvaluate underTest3 = new AuthStatementToEvaluate(
            Set.of(new StringMatchableExpression("resources/foo")),
            Set.of(new StringMatchableExpression("dynamic/${name}")),
            Set.of(new StringMatchableExpression("actions/baz"), new StringMatchableExpression("principals/bar")),
            null);
    assertFalse(underTest3.isFullyEnhanced());
  }
}