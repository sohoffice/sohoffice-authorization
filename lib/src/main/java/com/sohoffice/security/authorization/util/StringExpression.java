package com.sohoffice.security.authorization.util;

import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A wrapper class for string expression that can be lazily enhanced by variables.
 *
 * @param original   original string original
 * @param expression string expression that can be enhanced by variables
 */
public record StringExpression(
        String original,
        SimpleStringExpression expression
) implements Expression<StringExpression> {

  private static final Logger logger = LoggerFactory.getLogger(StringExpression.class);

  /**
   * Second constructor that expression is null and will be lazily initialized
   */
  public StringExpression(String original) {
    this(original, null);
  }

  /**
   * Check if the string is fully enhanced.
   * It is considered fully enhanced if expression is no longer dynamic.
   */
  public boolean isFullyEnhanced() {
    SimpleStringExpression exp = (expression == null) ? new SimpleStringExpression(this.original) : expression;
    return !exp.isDynamic();
  }

  public String getValue() {
    if (expression == null) {
      return original;
    }
    return expression.getValue();
  }

  @Override
  public Class<StringExpression> getExpressionType() {
    return StringExpression.class;
  }

  /**
   * Enhance the string expression with multiple attributes.
   * If a single attribute has multiple value, it will generates multiple enhanced string.
   *
   * @param attributes attributes input to enhance the string
   * @return The enhanced string expressions
   */
  @Override
  public Stream<StringExpression> enhance(@NotNull Collection<Map.Entry<String, String>> attributes) {
    Map<String, List<Map.Entry<String, String>>> grouped = attributes.stream()
            .collect(Collectors.groupingBy(Map.Entry::getKey));
    return grouped.entrySet().stream()
            .flatMap(entry -> {
              List<StringExpression> list = new ArrayList<>();
              for (Map.Entry<String, String> attribute : entry.getValue()) {
                StringExpression enhanced = this.enhance(attribute);
                // if the string is not enhanced, return the original string and no need to continue with other values
                if (Objects.equals(expression.getValue(), enhanced.getValue())) {
                  return Stream.of(this);
                }
                list.add(enhanced);
              }
              return list.stream();
            });
  }

  /**
   * Enhance the string with the given attribute.
   *
   * @param attribute The attribute to enhance the string.
   * @return The string after enhancement or the current instance if not enhanced.
   */
  public StringExpression enhance(Map.Entry<String, String> attribute) {
    boolean initializing = expression == null;
    SimpleStringExpression exp = initializing ? new SimpleStringExpression(original) : expression;
    if (exp.isDynamic()) {
      SimpleStringExpression exp2 = exp.withAttribute(attribute);
      if (Objects.equals(exp, exp2)) {
        // if the string expression is only initialized in this method, return new instance with right expression so that the enhancement can be tracked.
        if (initializing) {
          return new StringExpression(original, exp);
        }
        return this;
      }
      if (logger.isTraceEnabled()) {
        logger.trace("Enhanced string: {} -> {}, dynamic: {}.", original, exp2, exp2.isDynamic());
      }
      return new StringExpression(
              original,
              exp2
      );
    } else {
      return this;
    }
  }
}
