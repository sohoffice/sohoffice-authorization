package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.*;
import com.sohoffice.security.authorization.util.AttributesWithAccessor;
import com.sohoffice.security.authorization.util.StringExpression;
import com.sohoffice.security.authorization.util.WithAccessor;
import org.junit.jupiter.api.Test;

import java.util.*;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class IncrementalEvaluatorTest {

  private final AuthContextContributor contributor1 = new AuthContextContributor() {
    @Override
    public Result contribute(AuthContext context) {
      return new Result("contributor1", Set.of(Map.entry("name", "world")));
    }
  };
  private final AuthContextContributor contributor2 = new AuthContextContributor() {
    @Override
    public Result contribute(AuthContext input) {
      return new Result("contributor2", Set.of(Map.entry("foo", "bar"), Map.entry("name", "world1")));
    }
  };

  IncrementalEvaluator<AuthRequestTargetToEvaluate> underTest = new IncrementalEvaluator<>(
          new WithAccessor<>(ctx -> ctx.request().resourceRequests().stream()
                  .map(it -> new AuthRequestTargetToEvaluate(new StringExpression(it.resource()),
                                                             new StringExpression(it.action())))
                  .collect(Collectors.toSet()), (ctx, targets) -> {
            Set<AuthRequestTarget> results = targets.stream()
                    .map(it -> new AuthRequestTarget(it.resource().getValue(), it.action().getValue()))
                    .collect(Collectors.toSet());
            return ctx.withRequest(new AuthRequest(results));
          }),
          new AttributesWithAccessor<>(AuthContext::requestAttributes, AuthContext::withRequestAttributes),
          List.of(contributor1, contributor2));

  @Test
  void evaluate() {
    // Given request is only expanded into 1 result
    AuthContext context1 = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("resources/${foo}", "action1"))))
            .requestAttributes(new HashSet<>())
            .build();
    IncrementalEvaluator.EvaluationResult<AuthRequestTargetToEvaluate> result1 = underTest.evaluate(context1);
    assertThat(result1.context().requestResources())
            .containsOnly(new AuthRequestTarget("resources/bar", "action1"));

    // Given request is expanded into multiple results
    AuthContext context2 = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("names/${name}", "action2"))))
            .requestAttributes(new HashSet<>())
            .build();
    IncrementalEvaluator.EvaluationResult<AuthRequestTargetToEvaluate> result2 = underTest.evaluate(context2);
    assertThat(result2.context().requestResources())
            .containsOnly(new AuthRequestTarget("names/world", "action2"),
                          new AuthRequestTarget("names/world1", "action2"));

    // Given context has multiple requests
    AuthContext context3 = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("resources/${foo}", "action1"),
                                            new AuthRequestTarget("names/${name}", "action2"))))
            .requestAttributes(new HashSet<>())
            .build();
    IncrementalEvaluator.EvaluationResult<AuthRequestTargetToEvaluate> result3 = underTest.evaluate(context3);
    assertThat(result3.context().requestResources())
            .containsOnly(new AuthRequestTarget("resources/bar", "action1"),
                          new AuthRequestTarget("names/world", "action2"),
                          new AuthRequestTarget("names/world1", "action2"));

    // Given context has static requests
    AuthContext context4 = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("resources/${foo}", "action1"),
                                            new AuthRequestTarget("names/world", "action2"))))
            .requestAttributes(new HashSet<>())
            .build();
    IncrementalEvaluator.EvaluationResult<AuthRequestTargetToEvaluate> result4 = underTest.evaluate(context4);
    assertThat(result4.context().requestResources())
            .containsOnly(new AuthRequestTarget("resources/bar", "action1"),
                          new AuthRequestTarget("names/world", "action2"));
  }
}