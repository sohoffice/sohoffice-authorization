package com.sohoffice.security.authorization.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StringMatchableTest {

  @Test
  void matches() {
    StringMatchable matchable1 = new StringMatchable("Hello, world!");
    assertTrue(matchable1.matches("Hello, world!"));
    assertFalse(matchable1.matches("Hello, world"));

    StringMatchable matchable2 = new StringMatchable("Hello, *!");
    assertTrue(matchable2.matches("Hello, world!"));
    assertTrue(matchable2.matches("Hello, foo!"));
    assertFalse(matchable2.matches("Hello, !"));
    assertFalse(matchable2.matches("Hello, a/b!"));
    assertTrue(matchable2.matches("Hello, a:b!"));
  }
}