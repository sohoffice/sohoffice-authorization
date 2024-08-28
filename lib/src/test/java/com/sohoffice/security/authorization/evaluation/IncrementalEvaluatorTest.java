package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.*;
import com.sohoffice.security.authorization.util.*;
import org.junit.jupiter.api.Test;

import java.util.*;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class IncrementalEvaluatorTest {

  private final AuthContextContributor contributor1 = context ->
          new AuthContextContributor.Result("contributor1",
                                            Set.of(Map.entry("name", "world")));
  private final AuthContextContributor contributor2 = input ->
          new AuthContextContributor.Result("contributor2",
                                            Set.of(Map.entry("foo", "bar"), Map.entry("name", "world1")));

  IncrementalEvaluator<AuthRequestTargetToEvaluate, AuthRequestTargetToEvaluate> underTestAlwaysContinue = new IncrementalEvaluator<>(
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
          List.of(contributor1, contributor2),
          new AlwaysContinueAdapter());

  /**
   * Incremental evaluator that is only successful when it sees `resources/bar`
   */
  IncrementalEvaluator<AuthRequestTargetToEvaluate, TriStateBoolean> underTestLookForMatch = new IncrementalEvaluator<>(
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
          List.of(contributor1, contributor2),
          new LookForMatchAdapter("resources/bar"));

  @Test
  void evaluate_GivenAlwaysContinue_ThenExpandOne() {
    // Given request is only expanded into 1 result
    AuthContext context1 = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("resources/${foo}", "action1"))))
            .requestAttributes(new HashSet<>())
            .build();
    IncrementalEvaluator.Result<AuthRequestTargetToEvaluate, AuthRequestTargetToEvaluate> result1 = underTestAlwaysContinue.evaluate(
            context1);
    assertThat(result1.context().requestResources())
            .containsOnly(new AuthRequestTarget("resources/bar", "action1"));
  }

  @Test
  void evaluate_GivenAlwaysContinue_ThenExpandMultiple() {
    // Given request is expanded into multiple results
    AuthContext context2 = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("names/${name}", "action2"))))
            .requestAttributes(new HashSet<>())
            .build();
    IncrementalEvaluator.Result<AuthRequestTargetToEvaluate, AuthRequestTargetToEvaluate> result2 = underTestAlwaysContinue.evaluate(
            context2);
    assertThat(result2.context().requestResources())
            .containsOnly(new AuthRequestTarget("names/world", "action2"),
                          new AuthRequestTarget("names/world1", "action2"));
  }

  @Test
  void evaluate_GivenAlwaysContinue_WhenMultipleRequests() {
    // Given context has multiple requests
    AuthContext context3 = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("resources/${foo}", "action1"),
                                            new AuthRequestTarget("names/${name}", "action2"))))
            .requestAttributes(new HashSet<>())
            .build();
    IncrementalEvaluator.Result<AuthRequestTargetToEvaluate, AuthRequestTargetToEvaluate> result3 = underTestAlwaysContinue.evaluate(
            context3);
    assertThat(result3.context().requestResources())
            .containsOnly(new AuthRequestTarget("resources/bar", "action1"),
                          new AuthRequestTarget("names/world", "action2"),
                          new AuthRequestTarget("names/world1", "action2"));
  }

  @Test
  void evaluate_GivenAlwaysContinue_WhenStaticRequests() {
    // Given context has static requests
    AuthContext context4 = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("resources/${foo}", "action1"),
                                            new AuthRequestTarget("names/world", "action2"))))
            .requestAttributes(new HashSet<>())
            .build();
    IncrementalEvaluator.Result<AuthRequestTargetToEvaluate, AuthRequestTargetToEvaluate> result4 = underTestAlwaysContinue.evaluate(
            context4);
    assertThat(result4.context().requestResources())
            .containsOnly(new AuthRequestTarget("resources/bar", "action1"),
                          new AuthRequestTarget("names/world", "action2"));
  }

  @Test
  void evaluate_GivenLookForMatch_ThenExpandOne() {
    // Given request is only expanded into 1 result
    AuthContext context1 = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("resources/${foo}", "action1"))))
            .requestAttributes(new HashSet<>())
            .build();
    IncrementalEvaluator.Result<AuthRequestTargetToEvaluate, TriStateBoolean> result1 = underTestLookForMatch
            .evaluate(context1);
    assertThat(result1.result())
            .isEqualTo(TriStateBoolean.TRUE);
    assertThat(result1.context().requestResources())
            .containsOnly(new AuthRequestTarget("resources/bar", "action1"));
  }

  @Test
  void evaluate_GivenLookForMatch_ThenStopAtFirstMatch() {
    // Given request is only expanded into 1 result
    AuthContext context1 = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("names/${name}", "action2"),
                                            new AuthRequestTarget("resources/${foo}", "action1"),
                                            new AuthRequestTarget("expression/not-evaluated", "action3"))))
            .requestAttributes(new HashSet<>())
            .build();
    IncrementalEvaluator.Result<AuthRequestTargetToEvaluate, TriStateBoolean> result1 = underTestLookForMatch
            .evaluate(context1);
    assertThat(result1.result())
            .isEqualTo(TriStateBoolean.TRUE);
    assertThat(result1.context().requestResources())
            .containsOnly(new AuthRequestTarget("names/world", "action2"),
                          new AuthRequestTarget("names/world1", "action2"),
                          new AuthRequestTarget("resources/bar", "action1"));
  }

  private static class AlwaysContinueAdapter implements IncrementalEvaluator.EvaluationResultAdapter<AuthRequestTargetToEvaluate, AuthRequestTargetToEvaluate> {
    @Override
    public TriStateBoolean completedOne(AuthRequestTargetToEvaluate expression) {
      return TriStateBoolean.UNDEFINED;
    }

    @Override
    public AuthRequestTargetToEvaluate resultMapper(
            Either<AuthRequestTargetToEvaluate, AuthRequestTargetToEvaluate> expression) {
      return expression.success();
    }
  }

  private static class LookForMatchAdapter implements IncrementalEvaluator.EvaluationResultAdapter<AuthRequestTargetToEvaluate, TriStateBoolean> {
    private final String expected;

    private LookForMatchAdapter(String expected) {
      this.expected = expected;
    }

    @Override
    public TriStateBoolean completedOne(AuthRequestTargetToEvaluate expression) {
      return expression.isFullyEnhanced() &&
              Objects.equals(expression.resource().getValue(),
                             expected) ? TriStateBoolean.TRUE : TriStateBoolean.UNDEFINED;
    }

    @Override
    public TriStateBoolean resultMapper(
            Either<AuthRequestTargetToEvaluate, AuthRequestTargetToEvaluate> res) {
      return (res.successful()) ? TriStateBoolean.TRUE : TriStateBoolean.FALSE;
    }
  }
}