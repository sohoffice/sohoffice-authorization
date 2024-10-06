package com.sohoffice.security.authorization.evaluation;

public enum AuthPipelineStepResultStatus {
  AUTHORIZED,
  CONTINUE,
  STOP;

  public static AuthPipelineStepResultStatus fromBoolean(Boolean bool) {
    if (bool == null) {
      return CONTINUE;
    } else {
      return bool ? AUTHORIZED : STOP;
    }
  }
}
