package com.sohoffice.security.authorization.util;

public record Either<S, F>(
        boolean successful,
        S success,
        F failure
) {

  public static <S, F> Either<S, F> success(S success) {
    return new Either<>(true, success, null);
  }

  public static <S, F> Either<S, F> failure(F failure) {
    return new Either<>(false, null, failure);
  }
}
