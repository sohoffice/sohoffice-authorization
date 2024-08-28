package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.util.StringExpression;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuthRequestTargetToEvaluateTest {
  @Test
  void enhance_WhenWithValidAttributes_ThenReturnsEnhancedInstance() {
    StringExpression resource = new StringExpression("resource");
    StringExpression action = new StringExpression("action");
    AuthRequestTargetToEvaluate target = new AuthRequestTargetToEvaluate(resource, action);
    Map.Entry<String, String> attr = Map.entry("key", "value");

    AuthRequestTargetToEvaluate enhancedTarget = target.enhance(attr);

    assertNotNull(enhancedTarget);
    assertNotSame(target, enhancedTarget);
    assertTrue(enhancedTarget.resource().isFullyEnhanced());
    assertTrue(enhancedTarget.action().isFullyEnhanced());
  }

  @Test
  void getValue_ThenReturnsConcatenatedValue() {
    StringExpression resource = new StringExpression("resource");
    StringExpression action = new StringExpression("action");
    AuthRequestTargetToEvaluate target = new AuthRequestTargetToEvaluate(resource, action);

    String value = target.getValue();

    assertEquals("resource\taction", value);
  }

  @Test
  void getExpressionType_ThenReturnsCorrectClass() {
    StringExpression resource = new StringExpression("resource");
    StringExpression action = new StringExpression("action");
    AuthRequestTargetToEvaluate target = new AuthRequestTargetToEvaluate(resource, action);

    Class<AuthRequestTargetToEvaluate> expressionType = target.getExpressionType();

    assertEquals(AuthRequestTargetToEvaluate.class, expressionType);
  }

  @Test
  void isFullyEnhanced_WhenBothExpressionsAreFullyEnhanced_ThenReturnsTrue() {
    StringExpression resource = new StringExpression("resource", null);
    StringExpression action = new StringExpression("action", null);
    AuthRequestTargetToEvaluate target = new AuthRequestTargetToEvaluate(resource, action);

    assertTrue(target.isFullyEnhanced());
  }

  @Test
  void isFullyEnhanced_WhenAnyExpressionIsNotFullyEnhanced_ThenReturnsFalse() {
    StringExpression resource = new StringExpression("resource", null);
    StringExpression action = new StringExpression("actions/${action}", null);
    AuthRequestTargetToEvaluate target = new AuthRequestTargetToEvaluate(resource, action);

    assertFalse(target.isFullyEnhanced());
  }

}