package com.sohoffice.security.authorization.util;

/**
 * This interface defines an expression that aggregates multiple sub expressions.
 */
public interface Expressions<T extends Expressions<T>> extends Expression<T> {
  /**
   * Whether some sub expressions are completed, but not all
   */
  boolean isPartiallyCompleted();
}
