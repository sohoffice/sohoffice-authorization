package com.sohoffice.security.authorization.util;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public interface Expression<T extends Expression<T>> {
  default Stream<T> enhance(Collection<Map.Entry<String, String>> attributes) {
    Map<String, List<Map.Entry<String, String>>> grouped = attributes.stream()
            .collect(Collectors.groupingBy(Map.Entry::getKey));
    return grouped.entrySet().stream()
            .flatMap(entry -> {
              List<T> list = new ArrayList<>();
              for (Map.Entry<String, String> attribute : entry.getValue()) {
                T enhanced = this.enhance(attribute);
                // if the string is not enhanced, return the original string and no need to continue with other values
                if (Objects.equals(this.getValue(), enhanced.getValue())) {
                  return Stream.of(getExpressionType().cast(this));
                }
                list.add(enhanced);
              }
              return list.stream();
            });
  }

  T enhance(Map.Entry<String, String> attribute);

  String getValue();

  Class<T> getExpressionType();

  boolean isFullyEnhanced();
}
