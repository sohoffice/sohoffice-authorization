package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.AuthContext;
import com.sohoffice.security.authorization.AuthContextContributor;
import com.sohoffice.security.authorization.util.WithAccessor;
import com.sohoffice.security.authorization.util.AttributesWithAccessor;
import com.sohoffice.security.authorization.util.Expression;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

/**
 * An evaluator that can evaluate the expression incrementally.
 * <p/>
 * <ol>
 *  <li>It will first extract a set of expressions from the context context.</li>
 *  <li>It get current attributes from the context context</li>
 *  <li>Iterate through contributors, for each contributor, get the contributed attributes.</li>
 *  <li>Use the newly contributed attributes to enhanced the leftover expressions from last iteration.</li>
 *  <li>Combine the newly contributed attributes with the existing attributes.</li>
 *  <li>Enhance the expressions from beginning with all attributes.</li>
 * </ol>
 *
 * @param <T> Expression implementation type
 */
class IncrementalEvaluator<T extends Expression<T>> {
  private static final Logger logger = LoggerFactory.getLogger(IncrementalEvaluator.class);

  private final WithAccessor<AuthContext, Set<T>> targetsAccessor;
  private final AttributesWithAccessor<AuthContext> attributesAccessor;
  private final List<AuthContextContributor> contributors;

  public IncrementalEvaluator(@NotNull WithAccessor<AuthContext, Set<T>> evaluationTargetsAccessor,
                              @NotNull AttributesWithAccessor<AuthContext> attributesAccessor,
                              @NotNull List<AuthContextContributor> contributors) {
    this.targetsAccessor = evaluationTargetsAccessor;
    this.attributesAccessor = attributesAccessor;
    this.contributors = contributors;
  }

  public EvaluationResult<T> evaluate(AuthContext source) {
    Set<T> sourceTargets = targetsAccessor.get(source);
    Map<Boolean, Set<T>> initialClassification = sourceTargets.stream()
            .collect(Collectors.partitioningBy(Expression::isFullyEnhanced, Collectors.toSet()));

    // static expression are added to evaluated directly.
    Set<T> evaluated = new HashSet<>(initialClassification.getOrDefault(Boolean.TRUE, Collections.emptySet()));
    Set<T> sourceToBeEvaluated = initialClassification.getOrDefault(Boolean.FALSE, Collections.emptySet());
    Set<T> toBeEvaluated = Collections.emptySet();
    for (AuthContextContributor contributor : contributors) {
      Set<Map.Entry<String, String>> attributes = attributesAccessor.get(source);
      // first enhance the left over of last round
      if (logger.isTraceEnabled()) {
        logger.trace("Step 0, toBeEvaluated: {}, attributes: {}.", toBeEvaluated.size(), attributes.size());
      }
      Map<Boolean, List<T>> enhanced1 = toBeEvaluated.stream()
              .flatMap(it -> it.enhance(attributes))
              .collect(Collectors.groupingBy(Expression::isFullyEnhanced));
      evaluated.addAll(enhanced1.getOrDefault(Boolean.TRUE, Collections.emptyList()));
      toBeEvaluated = new HashSet<>(enhanced1.getOrDefault(Boolean.FALSE, Collections.emptyList()));
      // Add the new attributes back to the context
      AuthContextContributor.Result contributed = contributor.contribute(source);
      attributes.addAll(contributed.attributes());
      if (logger.isDebugEnabled()) {
        logger.debug("Step 1, Contributor {} attributes: {} -> {}.", contributed.contributorId(),
                     contributed.attributes().size(), attributes.size());
        if (logger.isTraceEnabled()) {
          logger.debug("Step 1, contributed attributes: {}", contributed.attributes());
        }
      }
      attributesAccessor.with(source, attributes);
      // then enhance the context with all attributes.
      Map<Boolean, List<T>> enhanced = sourceToBeEvaluated.stream()
              .flatMap(it -> it.enhance(attributes))
              .collect(Collectors.groupingBy(Expression::isFullyEnhanced));
      evaluated.addAll(enhanced.getOrDefault(Boolean.TRUE, Collections.emptyList()));
      toBeEvaluated.addAll(enhanced.getOrDefault(Boolean.FALSE, Collections.emptyList()));
      if (logger.isDebugEnabled()) {
        logger.debug("Step 2, evaluated: {}, toBeEvaluated: {}.", evaluated.size(), toBeEvaluated.size());
      }
    }
    return new EvaluationResult<>(targetsAccessor.with(source, evaluated), toBeEvaluated);
  }

  /**
   * The result of the {@link IncrementalEvaluator#evaluate(AuthContext)}.
   *
   * @param context      The context after evaluation.
   * @param notEvaluated The expressions that are not fully evaluated.
   * @param <T>          Expression implementation type
   */
  public record EvaluationResult<T extends Expression<T>>(
          AuthContext context,
          Set<T> notEvaluated
  ) {
  }
}
