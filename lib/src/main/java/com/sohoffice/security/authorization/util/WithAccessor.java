package com.sohoffice.security.authorization.util;

import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * A pair of getter and wither functions.
 *
 * @param <S> The source type
 * @param <V> The property value type
 */
public class WithAccessor<S, V> {
  private final Function<S, V> getter;
  private final BiFunction<S, V, S> wither;

  public WithAccessor(Function<S, V> getter, BiFunction<S, V, S> wither) {
    this.getter = getter;
    this.wither = wither;
  }

  public V get(S source) {
    return getter.apply(source);
  }

  public S with(S source, V value) {
    return wither.apply(source, value);
  }
}
