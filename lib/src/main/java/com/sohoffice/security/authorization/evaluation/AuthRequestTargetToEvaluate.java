package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.util.Expression;
import com.sohoffice.security.authorization.util.StringExpression;
import io.soabase.recordbuilder.core.RecordBuilder;

import java.util.Map;

@RecordBuilder
public record AuthRequestTargetToEvaluate(
        boolean fullyEnhanced,
        StringExpression resource,
        StringExpression action
) implements Expression<AuthRequestTargetToEvaluate>, AuthRequestTargetToEvaluateBuilder.With {

  public AuthRequestTargetToEvaluate(StringExpression v1, StringExpression v2) {
    this(v1.isFullyEnhanced() && v2.isFullyEnhanced(), v1, v2);
  }

  @Override
  public AuthRequestTargetToEvaluate enhance(Map.Entry<String, String> attr) {
    return new AuthRequestTargetToEvaluate(resource.enhance(attr), action.enhance(attr));
  }

  @Override
  public String getValue() {
    return resource.getValue() + "\t" + action.getValue();
  }

  @Override
  public Class<AuthRequestTargetToEvaluate> getExpressionType() {
    return AuthRequestTargetToEvaluate.class;
  }

  @Override
  public boolean isFullyEnhanced() {
    return resource().isFullyEnhanced() && action.isFullyEnhanced();
  }
}
