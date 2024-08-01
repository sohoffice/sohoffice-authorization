package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.*;
import com.sohoffice.security.authorization.util.AttributesWithAccessor;
import com.sohoffice.security.authorization.util.StringExpression;
import com.sohoffice.security.authorization.util.WithAccessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

/**
 * This pipeline step is used to enhance the resource request by combining with request contributors.
 * <p>
 * It will iterate through the request contributors and generate attributes to enhance the request.
 */
public class EnhanceRequestPipelineStep implements AuthPipelineStep {

  private static final Logger logger = LoggerFactory.getLogger(EnhanceRequestPipelineStep.class);

  @Override
  public AuthPipelineStepResult execute(AuthContext context) {
    // Use an IncrementalEvaluator to read {@link StringExpressionTuple} from the context and
    // enhance with attributes from contributors.
    IncrementalEvaluator<AuthRequestTargetToEvaluate> evaluator = new IncrementalEvaluator<>(
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
            context.requestContributors());
    IncrementalEvaluator.EvaluationResult<AuthRequestTargetToEvaluate> result = evaluator.evaluate(context);

    if (!result.notEvaluated().isEmpty()) {
      logger.warn("Some request contributors are not evaluated: {}", result.notEvaluated());
    }

    // The status should always be CONTINUE, as this is in the request stage where data is collected.
    // context is enhanced with the new targets.
    return new AuthPipelineStepResult(AuthPipelineStepResultStatus.CONTINUE,
                                      result.context());
  }
}
