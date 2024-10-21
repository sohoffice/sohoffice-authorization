package com.sohoffice.security.authorization.io;

import java.util.List;

public class AuthStatementModel implements AuthStatement{
  private final AuthStatementPb authStatementPb;

  public AuthStatementModel(AuthStatementPb authStatementPb) {
    this.authStatementPb = authStatementPb;
  }

  @Override
  public List<String> getResourcesList() {
    return authStatementPb.getResourcesList();
  }

  @Override
  public List<String> getPrincipalsList() {
    return authStatementPb.getPrincipalsList();
  }

  @Override
  public List<String> getActionsList() {
    return authStatementPb.getActionsList();
  }

  @Override
  public AuthEffect getEffect() {
    return authStatementPb.getEffect();
  }

  @Override
  public String getIdentifier() {
    return authStatementPb.getIdentifier();
  }

  public static AuthStatementModel of(List<String> resources, List<String> principals, List<String> actions, AuthEffect effect, String identifier) {
    return new AuthStatementModel(AuthStatementPb.newBuilder()
      .addAllResources(resources)
      .addAllPrincipals(principals)
      .addAllActions(actions)
      .setEffect(effect)
      .setIdentifier(identifier)
      .build());
  }
}
