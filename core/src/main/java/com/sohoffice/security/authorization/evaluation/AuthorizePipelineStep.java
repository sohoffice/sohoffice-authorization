package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.AuthContext;
import com.sohoffice.security.authorization.AuthRequest;
import com.sohoffice.security.authorization.AuthRequestTarget;
import com.sohoffice.security.authorization.io.AuthEffect;
import com.sohoffice.security.authorization.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * This pipeline step will get inputs from context and use it to evaluate whether the access request should be granted.
 * <p>
 * Inputs:
 * <ul>
 *   <li> Authorization statements from {@link AuthContext#authStatementProvider()} </li>
 *   <li> Profile attributes from {@link AuthContext#profileAttributes()} </li>
 * </ul>
 * Authorization target
 * <ul>
 *   <li> access request from {@link AuthContext#requestTargets()} </li>
 * </ul>
 * Outputs:
 * <ul>
 *   <li> If any evaluated authorization statement matches the authorization target, the access will be
 *   determined by the effect of this statement. </li>
 * </ul>
 */
public class AuthorizePipelineStep implements AuthPipelineStep {
  private static final Logger logger = LoggerFactory.getLogger(AuthorizePipelineStep.class);

  @Override
  public AuthPipelineStepResult execute(AuthContext ctx) {
    // Get all original auth statements
    Set<AuthStatementToEvaluate> authStatements = ctx.authStatementProvider().get().stream()
            .map(AuthStatementToEvaluate::ofAuthStatement)
            .collect(Collectors.toSet());
    ctx = ctx.withAuthStatements(authStatements);

    // Use IncrementalEvaluator to combine {@link ctx.authStatements()} with profile attributes to authorize resource request
    IncrementalEvaluator<AuthStatementToEvaluate, AuthorizePipeStepResult> evaluator = new IncrementalEvaluator<>(
            new WithAccessor<>(AuthContext::authStatements, AuthContext::withAuthStatements),
            new AttributesWithAccessor<>(AuthContext::profileAttributes, AuthContext::withProfileAttributes),
            ctx.profileContributors(),
            new Adapter(ctx.principals(), ctx.request()));

    IncrementalEvaluator.Result<AuthStatementToEvaluate, AuthorizePipeStepResult> result = evaluator.evaluate(ctx);

    AuthPipelineStepResultStatus nextStatus;
    String statementId = null;
    if (result.result() != null) {
      nextStatus = AuthPipelineStepResultStatus.fromBoolean(result.result().result());
      statementId = result.result().statementId();
    } else {
      nextStatus = AuthPipelineStepResultStatus.STOP;
    }
    return new AuthPipelineStepResult(nextStatus, result.context(), statementId);
  }

  private record AuthorizePipeStepResult(
          String statementId,
          boolean result
  ) {
  }

  private static class Adapter implements IncrementalEvaluator.EvaluationResultAdapter<AuthStatementToEvaluate, AuthorizePipeStepResult> {
    private final Set<String> principals;
    private final Set<String> resources;
    private final Set<String> actions;

    public Adapter(Set<String> principals, AuthRequest request) {
      this.principals = principals;
      resources = request.resourceTargets().stream()
              .map(AuthRequestTarget::resource)
              .collect(Collectors.toUnmodifiableSet());
      actions = request.resourceTargets().stream()
              .map(AuthRequestTarget::action)
              .collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public boolean supportPartiallyCompleted() {
      return true;
    }

    /**
     * Advise the result based on the auth statement object.
     *
     * @param expression The evaluated AuthStatement
     * @return Return TRUE (granted) or FALSE (rejected) according to auth effect in the statement
     * if principal/resource/action matches what is defined in the statement.
     * Otherwise, return UNDEFINED.
     */
    @Override
    public TriStateBoolean isCompleted(AuthStatementToEvaluate expression) {
      boolean principalMatched = expression.principals().stream()
              .filter(StringMatchableExpression::isFullyEnhanced)
              .map(StringMatchableExpression::toMatchable)
              .anyMatch(it -> principals.stream().anyMatch(it::matches));
      if (logger.isDebugEnabled()) {
        logger.debug("Principal matched: {}, request: {}, auth: {}", principalMatched, principals,
                     expression.principals());
      }
      if (principalMatched) {
        boolean resourceMatched = expression.resources().stream()
                .filter(StringMatchableExpression::isFullyEnhanced)
                .map(StringMatchableExpression::toMatchable)
                .anyMatch(it -> resources.stream().anyMatch(it::matches));
        if (logger.isDebugEnabled()) {
          logger.debug("Resource matched: {}, request: {}, auth: {}", resourceMatched, resources,
                       expression.resources());
        }
        boolean actionMatched = expression.actions().stream()
                .filter(StringMatchableExpression::isFullyEnhanced)
                .map(StringMatchableExpression::toMatchable)
                .anyMatch(it -> actions.stream().anyMatch(it::matches));
        if (logger.isDebugEnabled()) {
          logger.debug("Action matched: {}, request: {}, auth: {}", actionMatched, actions, expression.actions());
        }
        if (resourceMatched && actionMatched) {
          AuthEffect effect = expression.statement().getEffect();
          switch (effect) {
            case ALLOW:
              if (logger.isInfoEnabled()) {
                logger.info("Access granted by statement: {}", expression.statement().getIdentifier());
              }
              return TriStateBoolean.TRUE;
            case DENY:
              if (logger.isInfoEnabled()) {
                logger.info("Access denied by statement: {}", expression.statement().getIdentifier());
              }
              return TriStateBoolean.FALSE;
            case null:
            default:
              if (logger.isWarnEnabled()) {
                logger.warn("Unknown effect '{}' in auth statement: {}", effect, expression.statement().getIdentifier());
              }
              return TriStateBoolean.UNDEFINED;
          }
        } else {
          return TriStateBoolean.UNDEFINED;
        }
      } else {
        return TriStateBoolean.UNDEFINED;
      }
    }

    @Override
    public AuthorizePipeStepResult resultMapper(
            Either<AuthStatementToEvaluate, AuthStatementToEvaluate> internalResult) {
      String identifier = (internalResult.successful()) ?
              internalResult.success().statement().getIdentifier() : internalResult.failure().statement().getIdentifier();
      return new AuthorizePipeStepResult(identifier, internalResult.successful());
    }
  }
}
