package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.*;
import com.sohoffice.security.authorization.io.AuthEffect;
import com.sohoffice.security.authorization.io.AuthStatement;
import com.sohoffice.security.authorization.io.v1.AuthStatementV1;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class AuthorizePipelineStepTest {

  private final AuthorizePipelineStep underTest = new AuthorizePipelineStep();

  /**
   * DENY blacklist principals statement
   */
  private final AuthStatement stmt0 = new AuthStatementV1(
          List.of("resources/*"),
          List.of("principals/blacklist"),
          List.of("actions/*"),
          AuthEffect.DENY,
          "stmt0");

  /**
   * statement with single resource, principal, action
   */
  private final AuthStatement stmt1 = new AuthStatementV1(
          List.of("resources/${r1}"),
          List.of("principals/p1"),
          List.of("actions/action1"),
          AuthEffect.ALLOW,
          "stmt1");

  /**
   * principal with wildcard
   */
  private final AuthStatement stmt2 = new AuthStatementV1(
          List.of("resources/accounts/${a1}"),
          List.of("accounts/*"),
          List.of("actions/action2"),
          AuthEffect.ALLOW,
          "stmt2");

  /**
   * A static statement for ADMIN
   */
  private final AuthStatement stmt3 = new AuthStatementV1(
          List.of("resources/admin"),
          List.of("groups/ADMIN"),
          List.of("actions/admin"),
          AuthEffect.ALLOW,
          "stmt3");

  /**
   * Statement with multiple resources that needs to be enhanced
   */
  private final AuthStatement stmt4 = new AuthStatementV1(
          List.of("resources/${foo1}", "resources/${foo2}"),
          List.of("principals/*"),
          List.of("actions/admin"),
          AuthEffect.ALLOW,
          "stmt4");

  private final AuthContext baseContext = AuthContextBuilder.builder()
          .authStatementProvider(() -> List.of(stmt0, stmt1, stmt2, stmt3, stmt4))
          .profileAttributes(new HashSet<>())
          .build();

  @Test
  void execute_WhenExactlyMatched_ThenAllow() {
    AuthContext context = AuthContextBuilder.builder(baseContext)
            .request(new AuthRequest(Set.of(new AuthRequestTarget("resources/resource1", "actions/action1"))))
            .principals(Set.of("principals/p1"))
            .profileContributors(List.of(new TestAuthContextContributor("id1", Map.entry("r1", "resource1"))))
            .build();
    AuthPipelineStepResult res1 = underTest.execute(context);
    assertThat(res1).isNotNull();
    assertThat(res1.status()).isEqualTo(AuthPipelineStepResultStatus.AUTHORIZED);
    assertThat(res1.statementId()).isEqualTo("stmt1");
  }

  @Test
  void execute_WhenWildcardMatched_ThenAllow() {
    AuthContext context = AuthContextBuilder.builder(baseContext)
            .request(new AuthRequest(Set.of(new AuthRequestTarget("resources/accounts/123", "actions/action2"))))
            .principals(Set.of("accounts/123"))
            .profileContributors(List.of(new TestAuthContextContributor("id1", Map.entry("a1", "123"))))
            .build();
    AuthPipelineStepResult res2 = underTest.execute(context);
    assertThat(res2).isNotNull();
    assertThat(res2.status()).isEqualTo(AuthPipelineStepResultStatus.AUTHORIZED);
    assertThat(res2.statementId()).isEqualTo("stmt2");
  }

  @Test
  void execute_WhenMatchedButOnlyPartiallyEnhanced_ThenAllow() {
    AuthContext context = AuthContextBuilder.builder(baseContext)
            .request(new AuthRequest(Set.of(new AuthRequestTarget("resources/resource1", "actions/admin"))))
            .principals(Set.of("principals/p1"))
            .profileContributors(List.of(new TestAuthContextContributor("id1", Map.entry("foo2", "resource1"))))
            .build();
    AuthPipelineStepResult res4 = underTest.execute(context);
    assertThat(res4).isNotNull();
    assertThat(res4.status()).isEqualTo(AuthPipelineStepResultStatus.AUTHORIZED);
    assertThat(res4.statementId()).isEqualTo("stmt4");
  }
}