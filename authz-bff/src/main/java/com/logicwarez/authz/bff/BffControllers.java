package com.logicwarez.authz.bff;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

import com.logicwarez.authz.session.AuthorizationResolver;
import com.logicwarez.authz.session.SessionContext;
import com.logicwarez.authz.session.UserNotAuthorizedException;
import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint del contratto BFF di Quadrava (contracts/bff.yaml): ingresso del login, utente corrente, cambio di
 * tenant, logout; piu' la revoca delle sessioni per l'amministrazione.
 */
public final class BffControllers {

    /** Percorsi da lasciare pubblici nella SecurityFilterChain dell'applicazione. */
    public static final String[] PUBLIC_PATHS = {"/bff/login"};

    private static final Pattern TENANT = Pattern.compile("^[A-Za-z0-9_-]{1,50}$");
    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9._@-]{1,150}$");

    private BffControllers() {
    }

    static ResponseEntity<ProblemDetail> problem(HttpStatus status, String detail) {
        return ResponseEntity.of(ProblemDetail.forStatusAndDetail(status, detail)).build();
    }

    @RestController
    public static class LoginController {

        private final String registrationId;
        private final URI home;
        private final LoginSupport.Origins origins;

        public LoginController(BffProperties properties, LoginSupport.Origins origins) {
            this.registrationId = properties.oidc().registrationId();
            this.home = properties.frontend().loginSuccessUrl();
            this.origins = origins;
        }

        /**
         * Avvia il login OIDC e, a login fatto, torna a {@code return} (solo pagine delle applicazioni: niente
         * open redirect). Con una sessione gia' aperta torna subito indietro. Il tenant facoltativo viene
         * ricordato fino al ritorno dallo IAM; senza, il resolver sceglie l'ultimo usato.
         */
        @GetMapping("/bff/login")
        public ResponseEntity<?> login(@RequestParam(name = "return", required = false) String returnTo,
                                       @RequestParam(required = false) String tenant,
                                       HttpServletRequest request) {
            Optional<String> target = Optional.empty();
            if (returnTo != null) {
                target = origins.applicationUrl(returnTo, request);
                if (target.isEmpty()) {
                    return problem(HttpStatus.BAD_REQUEST, "Return page not allowed");
                }
            }
            if (tenant != null && !TENANT.matcher(tenant).matches()) {
                return problem(HttpStatus.BAD_REQUEST, "Invalid tenant");
            }
            if (tenant == null && SessionContext.from(request).isPresent()) {
                return ResponseEntity.status(HttpStatus.FOUND).location(target.map(URI::create).orElse(home)).build();
            }
            HttpSession session = request.getSession();
            if (tenant != null) {
                session.setAttribute(LoginSupport.TENANT_HINT, tenant);
            } else {
                session.removeAttribute(LoginSupport.TENANT_HINT);
            }
            if (target.isPresent()) {
                session.setAttribute(LoginSupport.RETURN_TO, target.get());
            } else {
                session.removeAttribute(LoginSupport.RETURN_TO);
            }
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(request.getContextPath() + "/oauth2/authorization/" + registrationId))
                    .build();
        }
    }

    @RestController
    public static class SessionController {

        private static final Logger log = LoggerFactory.getLogger(SessionController.class);

        private final LoginSupport.IamLogout iamLogout;
        private final AuthorizationResolver resolver;

        public SessionController(LoginSupport.IamLogout iamLogout, AuthorizationResolver resolver) {
            this.iamLogout = iamLogout;
            this.resolver = resolver;
        }

        /** Utente della sessione per la UI: niente token, niente identificativo di sessione, niente permessi. */
        @GetMapping("/bff/user")
        public UserView user(@AuthenticationPrincipal SessionContext session) {
            return UserView.of(session);
        }

        /**
         * Sposta la sessione su un altro dei tenant offerti all'utente: ruoli e permessi si risolvono di nuovo,
         * la scadenza assoluta resta quella del login. POST con token CSRF, mai GET.
         */
        @PostMapping("/bff/tenant")
        public ResponseEntity<?> switchTenant(@RequestBody TenantSelection body,
                                              @AuthenticationPrincipal SessionContext current,
                                              HttpServletRequest request) {
            if (body == null || body.tenant() == null || body.tenant().isBlank()) {
                return problem(HttpStatus.BAD_REQUEST, "Missing tenant");
            }
            if (!current.offersTenant(body.tenant())) {
                return problem(HttpStatus.NOT_FOUND, "Tenant not offered to the user");
            }
            AuthorizationResolver.Resolved resolved;
            try {
                resolved = resolver.resolve(current.username(), body.tenant());
            } catch (UserNotAuthorizedException e) {
                return problem(HttpStatus.NOT_FOUND, "Tenant not offered to the user");
            } catch (RuntimeException e) {
                log.error("Cambio di tenant fallito per {}: {}", current.username(), e.toString());
                return problem(HttpStatus.SERVICE_UNAVAILABLE, "Service temporarily unavailable");
            }
            request.getSession().setAttribute(SessionContext.ATTRIBUTE, new SessionContext(resolved.username(),
                    current.name(), resolved.email(), resolved.tenantId(), resolved.tenants(), resolved.roles(),
                    resolved.permissions(), current.createdAt(), current.expiresAt()));
            log.info("Cambio di tenant: utente={} tenant={}", resolved.username(), resolved.tenantId());
            return ResponseEntity.noContent().build();
        }

        @ExceptionHandler(HttpMessageNotReadableException.class)
        ResponseEntity<ProblemDetail> unreadable() {
            return problem(HttpStatus.BAD_REQUEST, "Invalid request body");
        }

        /**
         * Chiude la sessione (Spring Session cancella la chiave su Redis e fa scadere il cookie) e risponde con
         * l'indirizzo di logout sullo IAM, verso cui la pagina naviga per chiudere anche l'SSO.
         */
        @PostMapping("/logout")
        public LogoutResult logout(HttpServletRequest request) {
            HttpSession session = request.getSession(false);
            String idToken = null;
            if (session != null) {
                idToken = session.getAttribute(LoginSupport.ID_TOKEN) instanceof String t ? t : null;
                session.invalidate();
            }
            return new LogoutResult(iamLogout.logoutUrl(idToken));
        }

        public record TenantSelection(String tenant) {
        }

        public record LogoutResult(String redirect) {
        }

        /** Schema User di contracts/bff.yaml; tenants e currentTenant assenti se l'applicazione non li gestisce. */
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        public record UserView(String username, String name, String email, List<String> roles,
                               List<SessionContext.Tenant> tenants, String currentTenant) {

            static UserView of(SessionContext s) {
                return new UserView(s.username(), s.name(), s.email(), s.roles(), s.tenants(), s.tenantId());
            }
        }
    }

    /**
     * Revoca immediata delle sessioni di un utente, con l'indice per username standard di Spring Session
     * (repository "indexed"). authz.session.revoke: solo le sessioni sul tenant dell'amministratore;
     * authz.session.revokeglobal: tutte.
     */
    @RestController
    public static class SessionAdminController {

        public static final String REVOKE = "authz.session.revoke";
        public static final String REVOKE_GLOBAL = "authz.session.revokeglobal";

        private final ObjectProvider<FindByIndexNameSessionRepository<? extends Session>> sessions;

        public SessionAdminController(ObjectProvider<FindByIndexNameSessionRepository<? extends Session>> sessions) {
            this.sessions = sessions;
        }

        @DeleteMapping("/bff/admin/users/{username}/sessions")
        public ResponseEntity<?> revoke(@PathVariable String username, @AuthenticationPrincipal SessionContext admin) {
            if (!USERNAME.matcher(username).matches()) {
                return ResponseEntity.badRequest().build();
            }
            boolean global = admin.hasPermission(REVOKE_GLOBAL);
            if (!global && !admin.hasPermission(REVOKE)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
            FindByIndexNameSessionRepository<? extends Session> repository = sessions.getIfAvailable();
            if (repository == null) {
                return problem(HttpStatus.NOT_IMPLEMENTED,
                        "Revocation unavailable: set spring.session.data.redis.repository-type=indexed");
            }
            int revoked = 0;
            for (Map.Entry<String, ? extends Session> entry : repository.findByPrincipalName(username).entrySet()) {
                SessionContext target = entry.getValue().getAttribute(SessionContext.ATTRIBUTE);
                if (global || (target != null && Objects.equals(target.tenantId(), admin.tenantId()))) {
                    repository.deleteById(entry.getKey());
                    revoked++;
                }
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("username", username);
            body.put("tenant_id", global ? null : admin.tenantId());
            body.put("revoked_sessions", revoked);
            return ResponseEntity.ok(body);
        }
    }
}
