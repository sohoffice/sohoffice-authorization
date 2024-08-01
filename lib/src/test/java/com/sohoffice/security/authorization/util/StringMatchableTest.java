package com.sohoffice.security.authorization.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StringMatchableTest {

  @Test
  void match() {
    StringMatchable matchable1 = new StringMatchable("Hello, world!");
    assertTrue(matchable1.match("Hello, world!"));
    assertFalse(matchable1.match("Hello, world"));

    StringMatchable matchable2 = new StringMatchable("Hello, *!");
    assertTrue(matchable2.match("Hello, world!"));
    assertTrue(matchable2.match("Hello, foo!"));
    assertFalse(matchable2.match("Hello, !"));
    assertFalse(matchable2.match("Hello, a/b!"));
    assertTrue(matchable2.match("Hello, a:b!"));
  }
}