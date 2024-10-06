package com.sohoffice.security.authorization;

import com.sohoffice.security.authorization.evaluation.AuthStatementToEvaluate;
import com.sohoffice.security.authorization.io.AuthStatement;
import io.soabase.recordbuilder.core.RecordBuilder;
import org.jetbrains.annotations.NotNull;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * AuthContext is a record that represents the context of an authorization request.
 *
 * @param principals            The principals that are requesting the resource. It is always static from request.
 *                              Ex: user:alice, group:admin, role:admin
 * @param authStatementProvider The supplier to provide all auth statements.
 * @param authStatements        The auth statements provided from the supplier.
 * @param request               The evaluated application resource object to be requested.
 * @param requestContributors   Contributors to enhance the request.
 * @param profileAttributes     The claim attributes carried by the request.
 * @param profileContributors   Contributors to enhance the claim attributes.
 */
@RecordBuilder
public record AuthContext(
        @NotNull
        Set<String> principals,
        @NotNull
        Supplier<List<? extends AuthStatement>> authStatementProvider,
        Set<AuthStatementToEvaluate> authStatements,
        @NotNull
        AuthRequest request,
        @NotNull
        Set<Map.Entry<String, String>> requestAttributes,
        @NotNull
        List<AuthContextContributor> requestContributors,
        @NotNull
        Set<Map.Entry<String, String>> profileAttributes,
        @NotNull
        List<AuthContextContributor> profileContributors
) implements AuthContextBuilder.With {

  public Set<AuthRequestTarget> requestTargets() {
    return request.resourceTargets();
  }
}
