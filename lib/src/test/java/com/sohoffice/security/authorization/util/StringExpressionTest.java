package com.sohoffice.security.authorization.util;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class StringExpressionTest {

  private static final Map.Entry<String, String> context1 = Map.entry("name", "world");
  private static final Map.Entry<String, String> context2 = Map.entry("foo", "bar");

  @Test
  void test_isFullyEnhanced() {
    StringExpression undertest1 = new StringExpression("Hello, ${name}!", null);
    assertFalse(undertest1.isFullyEnhanced());

    StringExpression underTest2 = new StringExpression("Hello, world!", null);
    assertTrue(underTest2.isFullyEnhanced());

    StringExpression underTest3 = new StringExpression("Hello, ${name}!",
                                                       new SimpleStringExpression("Hello, ${name}!")
                                                               .withAttribute(Map.entry("name", "world")));
    assertTrue(underTest3.isFullyEnhanced());
  }

  @Test
  void test_enhance() {
    StringExpression undertest1 = new StringExpression("Hello, ${name}!", null);
    assertEquals("Hello, ${name}!", undertest1.getValue());
    assertFalse(undertest1.isFullyEnhanced());

    StringExpression r1 = undertest1.enhance(context1);
    assertEquals("Hello, world!", r1.getValue());
    assertTrue(r1.isFullyEnhanced());

    StringExpression undertest2 = new StringExpression("Hello, ${name}! ${foo} is not foo", null);
    StringExpression r2a = undertest2.enhance(context1);
    assertFalse(r2a.isFullyEnhanced());
    StringExpression r2b = r2a.enhance(context2);
    assertTrue(r2b.isFullyEnhanced());
    assertEquals("Hello, world! bar is not foo", r2b.getValue());
  }
}