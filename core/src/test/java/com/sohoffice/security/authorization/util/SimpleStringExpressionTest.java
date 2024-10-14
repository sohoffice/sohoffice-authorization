package com.sohoffice.security.authorization.util;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SimpleStringExpressionTest {

  @Test
  void expand() {
    SimpleStringExpression expandable1 = new SimpleStringExpression("Hello, ${name}!");
    assertEquals("Hello, world!", expandable1.expand("name", "world"));

    SimpleStringExpression expandable2 = new SimpleStringExpression("${foo} is not foo");
    assertEquals("bar is not foo", expandable2.expand("foo", "bar"));

    SimpleStringExpression expandable3 = new SimpleStringExpression("${foo}");
    assertEquals("bar", expandable3.expand("foo", "bar"));

    SimpleStringExpression expandable4 = new SimpleStringExpression("Hello, world!");
    assertEquals("Hello, world!", expandable4.expand("name", "world1"));
    assertFalse(expandable4.isDynamic());

    SimpleStringExpression expandable5 = new SimpleStringExpression("Incomplete ${name");
    assertEquals("Incomplete ${name", expandable5.expand("name", "world"));

    SimpleStringExpression expandable6 = new SimpleStringExpression("Incomplete name}");
    assertEquals("Incomplete name}", expandable6.expand("name", "world"));

    SimpleStringExpression expandable7 = new SimpleStringExpression("Hello, ${name}!");
    assertEquals("Hello, ${name}!", expandable7.expand("foo", "bar"));
  }

  @Test
  void equals() {
    SimpleStringExpression static1 = new SimpleStringExpression("Hello, world!");
    SimpleStringExpression static2 = new SimpleStringExpression("Hello, world!");
    assertEquals(static1, static2);

    SimpleStringExpression dynamic1 = new SimpleStringExpression("Hello, ${name}!");
    SimpleStringExpression dynamic2 = new SimpleStringExpression("Hello, ${name}!");
    assertEquals(dynamic1, dynamic2);

    assertEquals(dynamic1.withAttribute(Map.entry("name", "world")),
                 dynamic2.withAttribute(Map.entry("name", "world")));

    assertNotEquals(dynamic1.withAttribute(Map.entry("name", "world")), dynamic2);
  }
}
