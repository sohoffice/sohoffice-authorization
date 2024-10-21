package com.sohoffice.security.authorization.adapters.springbootweb.annotations;

import com.sohoffice.security.authorization.adapters.springbootweb.interceptors.AuthorizationInterceptor;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Add authorization to a request method.
 * This annotation should specify what resources it is accessing and what actions are being performed.
 * <p>
 * These annotations will be interpreted at runtime by the {@link AuthorizationInterceptor}
 * <p>
 * {@snippet :
 *
 * @Authorization(@Target(resource = "/features/foo", action = "features:create"))
 * public Foo createFoo(@Valid FooModel foo) {
 * return null;  // @replace regex="^.*$" replacement="  ..."
 * }
 *}
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Authorization {
  /**
   * Specify the authorization target
   */
  Target[] value();

  /**
   * The authorization target.
   * This annotation is combination of resource and the action being performed. Multiple resources and actions can
   * be specified, authorization policy will be matched if any of the target combination is matched.
   */
  @Retention(RetentionPolicy.RUNTIME)
  @interface Target {
    /**
     * The resource to be accessed.
     * <p>
     * Depending on the project, different formats can be used.
     * The recommendation is to use path style format, such as: `/features/foo`.
     * The REST API path can be a good example.
     */
    String[] resource();

    /**
     * The action to be performed.
     * <p>
     * Depending on the project, different formats can be used.
     * The recommendation is to use namespace plus a verb format, such as: `accounts:create`
     */
    String[] action();
  }
}
