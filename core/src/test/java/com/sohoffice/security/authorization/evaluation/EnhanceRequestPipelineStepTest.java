package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.*;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests of {@link EnhanceRequestPipelineStep}
 */
class EnhanceRequestPipelineStepTest {

  private final EnhanceRequestPipelineStep underTest = new EnhanceRequestPipelineStep();

  private final AuthContextContributor contributor1 = context ->
          new AuthContextContributor.Result("contributor1",
                                            Set.of(Map.entry("name", "world")));
  private final AuthContextContributor contributor2 = input ->
          new AuthContextContributor.Result("contributor2",
                                            Set.of(Map.entry("foo", "bar"), Map.entry("name", "world1")));

  /**
   * Validate static request target to prove the interaction with {@link IncrementalEvaluator} is good.
   */
  @Test
  void execute_WhenStaticRequestTarget_ThenReturnStatic() {
    AuthContext context = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("resource", "action"))))
            .requestContributors(List.of(contributor1, contributor2))
            .requestAttributes(new HashSet<>())
            .build();
    AuthPipelineStepResult result = underTest.execute(context);
    assertThat(result.context().requestTargets())
            .containsOnly(new AuthRequestTarget("resource", "action"));
    assertThat(result.status())
            .isEqualTo(AuthPipelineStepResultStatus.CONTINUE);
  }

  @Test
  void execute_WhenResolvableRequestTarget_ThenReturnTheResolved() {
    AuthContext context = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("resources/${foo}", "action1"))))
            .requestContributors(List.of(contributor1, contributor2))
            .requestAttributes(new HashSet<>())
            .build();
    AuthPipelineStepResult result = underTest.execute(context);
    assertThat(result.context().requestTargets())
            .containsOnly(new AuthRequestTarget("resources/bar", "action1"));
    assertThat(result.status())
            .isEqualTo(AuthPipelineStepResultStatus.CONTINUE);
  }

  @Test
  void execute_WhenNonResolvableRequestTarget_ThenReturnEmpty() {
    AuthContext context = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("names/${non-resolvable-1}", "action1"),
                                            new AuthRequestTarget("names/${non-resolvable-2}", "action2"))))
            .requestContributors(List.of(contributor1, contributor2))
            .requestAttributes(new HashSet<>())
            .build();
    AuthPipelineStepResult result = underTest.execute(context);
    assertThat(result.context().requestTargets())
            .isEmpty();
    assertThat(result.status())
            .isEqualTo(AuthPipelineStepResultStatus.CONTINUE);
  }

  @Test
  void execute_WhenMixedRequestTarget_ThenReturnResolvedAndStatic() {
    AuthContext context = AuthContextBuilder.builder()
            .request(new AuthRequest(Set.of(new AuthRequestTarget("resources/${foo}", "action1"),
                                            new AuthRequestTarget("names/${not-resolvable}", "action2"),
                                            new AuthRequestTarget("names/${name}", "action3"))))
            .requestContributors(List.of(contributor1, contributor2))
            .requestAttributes(new HashSet<>())
            .build();
    AuthPipelineStepResult result = underTest.execute(context);
    assertThat(result.context().requestTargets())
            .containsOnly(new AuthRequestTarget("resources/bar", "action1"),
                          new AuthRequestTarget("names/world", "action3"),
                          new AuthRequestTarget("names/world1", "action3"));
    assertThat(result.status())
            .isEqualTo(AuthPipelineStepResultStatus.CONTINUE);
  }
}