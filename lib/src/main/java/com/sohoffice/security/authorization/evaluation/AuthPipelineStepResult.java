package com.sohoffice.security.authorization.evaluation;

import com.sohoffice.security.authorization.AuthContext;

public record AuthPipelineStepResult(
        AuthPipelineStepResultStatus status,
        AuthContext context
) {
}
