package com.sohoffice.security.authorization.util;

import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * A specialized WithAccessor for attributes.
 *
 * @param <S> The source type
 */
public class AttributesWithAccessor<S> extends WithAccessor<S, Set<Map.Entry<String, String>>> {
  public AttributesWithAccessor(Function<S, Set<Map.Entry<String, String>>> getter,
                                BiFunction<S, Set<Map.Entry<String, String>>, S> wither) {
    super(getter, wither);
  }
}
