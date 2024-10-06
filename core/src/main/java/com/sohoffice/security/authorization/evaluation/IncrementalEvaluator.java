package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.AuthContext;
import com.sohoffice.security.authorization.AuthContextContributor;
import com.sohoffice.security.authorization.util.*;
import io.soabase.recordbuilder.core.RecordBuilder;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
 * @param <R> The evaluation result type
 */
class IncrementalEvaluator<T extends Expression<T>, R> {
  private static final Logger logger = LoggerFactory.getLogger(IncrementalEvaluator.class);

  private final WithAccessor<AuthContext, Set<T>> targetsAccessor;
  private final AttributesWithAccessor<AuthContext> attributesAccessor;
  private final List<AuthContextContributor> contributors;
  private final EvaluationResultAdapter<T, R> evaluationResultAdapter;

  public IncrementalEvaluator(@NotNull WithAccessor<AuthContext, Set<T>> evaluationTargetsAccessor,
                              @NotNull AttributesWithAccessor<AuthContext> attributesAccessor,
                              @NotNull List<AuthContextContributor> contributors,
                              @NotNull IncrementalEvaluator.EvaluationResultAdapter<T, R> evaluationResultAdapter) {
    this.targetsAccessor = evaluationTargetsAccessor;
    this.attributesAccessor = attributesAccessor;
    this.contributors = contributors;
    this.evaluationResultAdapter = evaluationResultAdapter;
  }

  public Result<T, R> evaluate(final AuthContext source) {
    // Create an array of lazily evaluation suppliers. The first the evaluate any result become the final result.
    List<InternalEvaluator<T>> evaluationFunctions = new ArrayList<>();

    // static expression are added to evaluated directly.
    Set<T> sourceTargets = targetsAccessor.get(source);
    Map<Boolean, Set<T>> initialClassification = sourceTargets.stream()
            .collect(Collectors.partitioningBy(Expression::isFullyEnhanced, Collectors.toSet()));

    // First evaluation function evaluates static expressions.
    evaluationFunctions.add(context -> {
      // 1. Classify enhanced and not enhanced
      //    Already done above, skipped.

      // 2. Update classified expressions to context
      context = context.withExpressions(initialClassification);
      // 3. Evaluate the enhanced expression
      return evaluateEnhanced(context, initialClassification);
    });

    contributors.forEach(contributor -> evaluateContributor(contributor).forEach(evaluationFunctions::add));

    InternalContext<T> internalContext =
            new InternalContext<>(source, new HashSet<>(), new HashSet<>(),
                                  initialClassification.getOrDefault(Boolean.FALSE, Collections.emptySet()));
    for (InternalEvaluator<T> evaluator : evaluationFunctions) {
      logger.debug("---- 1, Requests: {}.", internalContext.authContext.request());
      InternalResult<T> result = evaluator.evaluate(internalContext);
      // Return if the evaluation result is not null
      if (result.result() != null) {
        return new Result<>(evaluationResultAdapter.resultMapper(result.result()),
                            result.context().authContext(),
                            result.context().toBeEnhanced());
      }
      AuthContext authContext = result.context().authContext();
      authContext = targetsAccessor.with(authContext, result.context().enhanced());
      internalContext = result.context().withAuthContext(authContext);
      logger.debug("---- 2, Requests: {}.", internalContext.authContext.request());
    }

    return new Result<>(null, internalContext.authContext(), internalContext.toBeEnhanced());
  }

  private @NotNull Stream<InternalEvaluator<T>> evaluateContributor(AuthContextContributor contributor) {
    return Stream.of(this::evaluatePopulateAttributes,
                     context -> doEvaluateContributor(contributor, context));
  }

  /**
   * Use the attributes in the context to evaluate the not enhanced expressions.
   *
   * @param context Evaluation context
   * @return The evaluation result
   */
  private @NotNull InternalResult<T> evaluatePopulateAttributes(InternalContext<T> context) {
    // A. Enhance the left over of last round
    AuthContext authContext = context.authContext();
    Set<Map.Entry<String, String>> attributes = attributesAccessor.get(authContext);
    Collection<T> toBeEnhanced = context.toBeEnhanced();
    if (logger.isTraceEnabled()) {
      logger.trace("Step A, toBeEnhanced: {}, attributes: {}.", toBeEnhanced.size(), attributes.size());
    }
    // A.1. Enhance expression and classify the result
    Map<Boolean, Set<T>> enhancedMap = toBeEnhanced.stream()
            .flatMap(it -> it.enhance(attributes))
            .collect(Collectors.groupingBy(Expression::isFullyEnhanced, HashMap::new, Collectors.toSet()));

    // A.2. Update classified expressions to context
    context = context.withExpressions(enhancedMap);
    // A.3. Evaluate the enhanced expression
    return evaluateEnhanced(context, enhancedMap);
  }

  /**
   * Actually call the contributor to contribute attributes and do evaluation thereafter
   *
   * @param contributor Contributor instance
   * @param context     evaluation context
   * @return The evaluation result
   */
  private @NotNull InternalResult<T> doEvaluateContributor(AuthContextContributor contributor,
                                                           InternalContext<T> context) {
    AuthContext authContext = context.authContext();
    Set<Map.Entry<String, String>> attributes = attributesAccessor.get(authContext);
    // B. Contributor contributes
    AuthContextContributor.Result contributed = contributor.contribute(authContext);
    attributes.addAll(contributed.attributes());
    if (logger.isDebugEnabled()) {
      logger.debug("Step B, Contributor {} attributes count: {} -> {}.", contributed.contributorId(),
                   contributed.attributes().size(), attributes.size());
      if (logger.isTraceEnabled()) {
        logger.debug("        Attributes: {}", contributed.attributes());
      }
    }
    // B.1. Update attribute to AuthContext
    authContext = attributesAccessor.with(authContext, attributes);
    context = context.withAuthContext(authContext);

    // C. Enhance the context with all attributes.
    // C.1. Classify enhanced and not enhanced
    Map<Boolean, Set<T>> enhancedMap = context.initToBeEnhanced().stream()
            .flatMap(it -> it.enhance(attributes))
            .collect(Collectors.groupingBy(Expression::isFullyEnhanced, HashMap::new, Collectors.toSet()));
    Set<T> enhanced2 = enhancedMap.getOrDefault(Boolean.TRUE, Collections.emptySet());
    // C.2. Update classified expressions to context
    context = context.withExpressions(enhancedMap);
    if (logger.isDebugEnabled()) {
      logger.debug("Step C, enhanced: {}, toBeEnhanced: {}.", enhanced2.size(), context.toBeEnhanced().size());
    }
    // C.3. Evaluate the enhanced expression
    return evaluateEnhanced(context, enhancedMap);
  }

  private InternalResult<T> evaluateEnhanced(InternalContext<T> context,
                                             Map<Boolean, Set<T>> expressionMap) {
    Set<T> toBeEvaluated;
    if (evaluationResultAdapter.supportPartiallyCompleted()) {
      // evaluate all results
      toBeEvaluated = expressionMap.values().stream()
              .flatMap(Collection::stream)
              .collect(Collectors.toSet());
    } else {
      // evaluate only completed results
      toBeEvaluated = expressionMap.getOrDefault(Boolean.TRUE, Collections.emptySet());
    }
    Either<T, T> result = evaluateCompletion(toBeEvaluated);
    logger.debug("Step D, evaluated to: {}", result);
    AuthContext authContext = targetsAccessor.with(context.authContext(), toBeEvaluated);
    context = context.withExpressions(expressionMap)
            .withAuthContext(authContext);

    if (result == null) {
      return new InternalResult<>(null, context);
    }
    return new InternalResult<>(result, context);
  }

  private Either<T, T> evaluateCompletion(Collection<T> expressions) {
    return expressions.stream()
            .map(it -> Map.entry(it, evaluationResultAdapter.isCompleted(it)))
            .filter(it -> it.getValue() != TriStateBoolean.UNDEFINED)
            .findFirst()
            .map(it -> new Either<>(it.getValue() == TriStateBoolean.TRUE, it.getKey(), it.getKey()))
            .orElse(null);
  }

  /**
   * Adapter interface to determine whether the evaluation is completed and mapping to result
   *
   * @param <T>
   * @param <R>
   */
  public interface EvaluationResultAdapter<T extends Expression<T>, R> {
    /**
     * Whether the partially completed rules can be evaluated for completion, via {@link #isCompleted(T)}.
     */
    default boolean supportPartiallyCompleted() {
      return false;
    }

    /**
     * Determine whether the specified expression is completed.
     *
     * @param expression Input expression
     * @return {@link TriStateBoolean#UNDEFINED} if the result still cannot be decided.
     * Otherwise use {@link com.sohoffice.security.authorization.io.AuthStatement#effect()} to determine the result.
     */
    TriStateBoolean isCompleted(T expression);

    /**
     * Convert the internal result to the final result.
     *
     * @param internalResult Internal result
     * @return The converted final results
     */
    R resultMapper(Either<T, T> internalResult);
  }

  /**
   * Internal evaluation context
   *
   * @param authContext      Auth context
   * @param toBeEnhanced     The accumulated expressions to be enhanced.
   * @param initToBeEnhanced The original expressions to be enhanced.
   * @param <T>
   */
  private record InternalContext<T>(AuthContext authContext,
                                    Set<T> enhanced,
                                    Set<T> toBeEnhanced,
                                    Set<T> initToBeEnhanced) {

    public InternalContext {
      toBeEnhanced = Collections.unmodifiableSet(toBeEnhanced);
      initToBeEnhanced = Collections.unmodifiableSet(initToBeEnhanced);
    }

    public InternalContext<T> withAuthContext(AuthContext context) {
      return new InternalContext<>(context, enhanced(), toBeEnhanced(), initToBeEnhanced());
    }

    public InternalContext<T> withExpressions(Map<Boolean, Set<T>> enhanceMap) {
      return withExpressions(enhanceMap.getOrDefault(Boolean.TRUE, Collections.emptySet()),
                             enhanceMap.getOrDefault(Boolean.FALSE, Collections.emptySet()));
    }

    public InternalContext<T> withExpressions(Set<T> enhanced2, Set<T> toBeEnhanced2) {
      Set<T> enhancedNew = new HashSet<>(enhanced());
      enhancedNew.addAll(enhanced2);
      Set<T> toBeEnhancedNew = new HashSet<>(toBeEnhanced());
      toBeEnhancedNew.addAll(toBeEnhanced2);
      return new InternalContext<>(authContext(), enhancedNew, toBeEnhancedNew, initToBeEnhanced());
    }
  }

  /**
   * Internal and intermediate result produced by {@link InternalEvaluator}
   *
   * @param result  The evaluated result. Null if nothing is found, otherwise the result.
   * @param context The context after evaluation.
   * @param <T>
   */
  private record InternalResult<T extends Expression<T>>(
          Either<T, T> result,
          InternalContext<T> context
  ) {
  }

  /**
   * Internal evaluator to simplifies complex java.util.Function declaration.
   *
   * @param <T>
   */
  @FunctionalInterface
  private interface InternalEvaluator<T extends Expression<T>> {
    InternalResult<T> evaluate(InternalContext<T> context);
  }

  /**
   * The result of the {@link IncrementalEvaluator#evaluate(AuthContext)}.
   *
   * @param context      The context after evaluation.
   * @param notEvaluated The expressions that are not fully evaluated.
   * @param <T>          Expression implementation type
   */
  @RecordBuilder
  public record Result<T extends Expression<T>, R>(
          R result,
          AuthContext context,
          Collection<T> notEvaluated
  ) {
  }

}
