package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.io.AuthEffect;
import com.sohoffice.security.authorization.util.Expression;
import com.sohoffice.security.authorization.util.StringExpression;
import io.soabase.recordbuilder.core.RecordBuilder;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RecordBuilder
public record StatementToEvaluate(
        List<StringExpression> resources,
        List<StringExpression> principals,
        List<StringExpression> actions,
        AuthEffect effect,
        String identifier
) implements Expression<StatementToEvaluate>, StatementToEvaluateBuilder.With {
  @Override
  public StatementToEvaluate enhance(Map.Entry<String, String> attribute) {
    return this
            .withResources(resources.stream().map(r -> r.enhance(attribute)).toList())
            .withPrincipals(principals.stream().map(p -> p.enhance(attribute)).toList())
            .withActions(actions.stream().map(a -> a.enhance(attribute)).toList());
  }

  @Override
  public String getValue() {
    return resources.stream().map(StringExpression::getValue).collect(Collectors.joining(", ")) + "\t" +
            principals.stream().map(StringExpression::getValue).collect(Collectors.joining(", ")) + "\t" +
            actions.stream().map(StringExpression::getValue).collect(Collectors.joining(", ")) + "\t" +
            effect + "\t" +
            identifier;
  }

  @Override
  public Class<StatementToEvaluate> getExpressionType() {
    return StatementToEvaluate.class;
  }

  @Override
  public boolean isFullyEnhanced() {
    return resources.stream().allMatch(StringExpression::isFullyEnhanced) &&
            principals.stream().allMatch(StringExpression::isFullyEnhanced) &&
            actions.stream().allMatch(StringExpression::isFullyEnhanced);
  }
}
