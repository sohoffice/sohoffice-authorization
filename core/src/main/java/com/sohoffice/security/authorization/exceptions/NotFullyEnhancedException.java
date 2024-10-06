package com.sohoffice.security.authorization.exceptions;

/**
 * Thrown if a string expression is not fully enhanced and cannot continue with the operation.
 */
public class NotFullyEnhancedException extends SohofficeAuthException {
  public NotFullyEnhancedException(String expression) {
    super("The expression is '%s' not fully enhanced".formatted(expression));
  }
}
