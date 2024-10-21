package com.sohoffice.security.authorization.adapters.springbootweb.interceptors;

import com.sohoffice.security.authorization.adapters.springbootweb.annotations.Authorization;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

public class AuthorizationInterceptor implements HandlerInterceptor {
  @Override
  public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object handler) throws Exception {
    if(handler != null) {
      Authorization authorization = handler.getClass().getAnnotation(Authorization.class);
    }
    return HandlerInterceptor.super.preHandle(req, res, handler);
  }
}
