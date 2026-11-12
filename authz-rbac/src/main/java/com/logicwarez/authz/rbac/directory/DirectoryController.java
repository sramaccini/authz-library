package com.logicwarez.authz.rbac.directory;

import java.util.List;

import com.logicwarez.authz.rbac.directory.TenantDirectory.DirectoryUser;
import com.logicwarez.authz.session.SessionContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code GET /api/v1/directory/users?q=&limit=}: utenti attivi del tenant della sessione, per i selettori
 * dell'interfaccia. Esposto solo con {@code authz.rbac.directory.permission}, il permesso dell'applicazione che serve
 * per leggerlo.
 */
@RestController
public class DirectoryController {

    private final TenantDirectory directory;
    private final String permission;

    public DirectoryController(TenantDirectory directory, String permission) {
        this.directory = directory;
        this.permission = permission;
    }

    @GetMapping("/api/v1/directory/users")
    public ResponseEntity<?> users(@AuthenticationPrincipal SessionContext session,
                                   @RequestParam(required = false) String q,
                                   @RequestParam(defaultValue = "20") int limit) {
        if (!session.hasPermission(permission)) {
            return ResponseEntity.of(ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN,
                    "Missing permission " + permission)).build();
        }
        if (session.tenantId() == null) {
            return ResponseEntity.of(ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, "No tenant in the session"))
                    .build();
        }
        List<DirectoryUser> users = directory.search(session.tenantId(), q, limit);
        return ResponseEntity.ok(users);
    }
}
