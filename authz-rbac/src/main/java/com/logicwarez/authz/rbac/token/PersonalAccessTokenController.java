package com.logicwarez.authz.rbac.token;

import java.util.UUID;

import com.logicwarez.authz.session.SessionContext;
import com.logicwarez.authz.session.TokenAuthentication;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Token di accesso personali dell'utente della sessione ({@code authz.rbac.tokens.enabled}). Si gestiscono solo da
 * una sessione del browser: una richiesta fatta con un token non crea, elenca ne' revoca token (403).
 */
@RestController
@RequestMapping("/api/v1/tokens")
public class PersonalAccessTokenController {

    private final PersonalAccessTokens tokens;

    public PersonalAccessTokenController(PersonalAccessTokens tokens) {
        this.tokens = tokens;
    }

    /** @param expiresInDays durata in giorni, al massimo authz.rbac.tokens.max-days; predefinita 90 */
    public record CreateRequest(@NotBlank @Size(max = 100) String name, @Min(1) Integer expiresInDays) {
    }

    @GetMapping
    public ResponseEntity<?> list(Authentication authentication) {
        return session(authentication) instanceof SessionContext s
                ? ResponseEntity.ok(tokens.list(s.username())) : browserOnly();
    }

    @PostMapping
    public ResponseEntity<?> create(Authentication authentication, @Valid @RequestBody CreateRequest request) {
        if (!(session(authentication) instanceof SessionContext s)) {
            return browserOnly();
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(tokens.create(s.username(), request.name().strip(),
                request.expiresInDays() == null ? PersonalAccessTokens.DEFAULT_DAYS : request.expiresInDays()));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> revoke(Authentication authentication, @PathVariable UUID id) {
        if (!(session(authentication) instanceof SessionContext s)) {
            return browserOnly();
        }
        tokens.revoke(s.username(), id);
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(PersonalAccessTokens.TokenException.class)
    ResponseEntity<ProblemDetail> tokenProblem(PersonalAccessTokens.TokenException e) {
        return ResponseEntity.of(ProblemDetail.forStatusAndDetail(HttpStatus.valueOf(e.status()), e.getMessage()))
                .build();
    }

    /** Il contesto di una sessione del browser, null per una richiesta con un token. */
    private static SessionContext session(Authentication authentication) {
        return authentication instanceof TokenAuthentication ? null
                : authentication != null && authentication.getPrincipal() instanceof SessionContext s ? s : null;
    }

    private static ResponseEntity<ProblemDetail> browserOnly() {
        return ResponseEntity.of(ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN,
                "Personal access tokens are managed from a browser session")).build();
    }
}
