package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.AuthContext;

public interface AuthPipelineStep {

  AuthPipelineStepResult execute(AuthContext ctx);
}
