package com.logicwarez.authz.bff;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

import com.logicwarez.authz.session.SessionContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Sessioni dell'utente collegato (ASVS 3.3.4): elenco con dispositivo e ultimo accesso, chiusura di una sessione o di
 * tutte le altre. Usa l'indice per username di Spring Session (repository "indexed"); senza, {@code 501}.
 */
public final class UserSessions {

    /** Attributi di sessione scritti al login. */
    static final String CLIENT_IP = "authz.bff.client_ip";
    static final String USER_AGENT = "authz.bff.user_agent";
    static final String OIDC_SID = "authz.bff.oidc_sid";
    static final String OIDC_SUB = "authz.bff.oidc_sub";

    static final int USER_AGENT_MAX = 256;
    private static final Pattern ID = Pattern.compile("^[0-9a-f]{32}$");

    private UserSessions() {
    }

    /**
     * Una sessione come la vede l'utente o l'amministratore. {@code id} e' un hash dell'identificativo della
     * sessione: non e' il valore del cookie e non permette di usarla.
     */
    public record SessionView(String id, Instant createdAt, Instant lastAccessedAt, String ipAddress,
                              String userAgent, String tenant, boolean current) {
    }

    /** Identificativo pubblico della sessione: i primi 16 byte dello SHA-256 dell'id, in esadecimale. */
    static String publicId(String sessionId) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(sessionId.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static SessionView view(Session session, String currentId) {
        SessionContext context = session.getAttribute(SessionContext.ATTRIBUTE);
        return new SessionView(publicId(session.getId()), session.getCreationTime(), session.getLastAccessedTime(),
                session.getAttribute(CLIENT_IP), session.getAttribute(USER_AGENT),
                context == null ? null : context.tenantId(), session.getId().equals(currentId));
    }

    static List<SessionView> views(Map<String, ? extends Session> sessions, String currentId) {
        return sessions.values().stream()
                .map(s -> view(s, currentId))
                .sorted(Comparator.comparing(SessionView::lastAccessedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .toList();
    }

    /** {@code /bff/sessions}: solo con la sessione del browser (le richieste con un token non arrivano qui). */
    @RestController
    public static class UserSessionController {

        private final ObjectProvider<FindByIndexNameSessionRepository<? extends Session>> sessions;

        public UserSessionController(ObjectProvider<FindByIndexNameSessionRepository<? extends Session>> sessions) {
            this.sessions = sessions;
        }

        @GetMapping("/bff/sessions")
        public ResponseEntity<?> list(@AuthenticationPrincipal SessionContext user, HttpServletRequest request) {
            FindByIndexNameSessionRepository<? extends Session> repository = sessions.getIfAvailable();
            if (repository == null) {
                return unavailable();
            }
            return ResponseEntity.ok(views(repository.findByPrincipalName(user.username()), currentId(request)));
        }

        /** Chiude una sessione dell'utente, anche quella corrente (come un logout senza uscire dallo IAM). */
        @DeleteMapping("/bff/sessions/{id}")
        public ResponseEntity<?> end(@PathVariable String id, @AuthenticationPrincipal SessionContext user,
                                     HttpServletRequest request) {
            if (!ID.matcher(id).matches()) {
                return BffControllers.problem(HttpStatus.BAD_REQUEST, "Invalid session id");
            }
            FindByIndexNameSessionRepository<? extends Session> repository = sessions.getIfAvailable();
            if (repository == null) {
                return unavailable();
            }
            String current = currentId(request);
            for (String sessionId : repository.findByPrincipalName(user.username()).keySet()) {
                if (publicId(sessionId).equals(id)) {
                    if (sessionId.equals(current)) {
                        request.getSession().invalidate();
                    } else {
                        repository.deleteById(sessionId);
                    }
                    return ResponseEntity.noContent().build();
                }
            }
            return BffControllers.problem(HttpStatus.NOT_FOUND, "Unknown session");
        }

        /** Chiude tutte le sessioni dell'utente tranne quella della richiesta. */
        @DeleteMapping("/bff/sessions")
        public ResponseEntity<?> endOthers(@AuthenticationPrincipal SessionContext user, HttpServletRequest request) {
            FindByIndexNameSessionRepository<? extends Session> repository = sessions.getIfAvailable();
            if (repository == null) {
                return unavailable();
            }
            String current = currentId(request);
            repository.findByPrincipalName(user.username()).keySet().stream()
                    .filter(sessionId -> !Objects.equals(sessionId, current))
                    .forEach(repository::deleteById);
            return ResponseEntity.noContent().build();
        }

        private static String currentId(HttpServletRequest request) {
            HttpSession session = request.getSession(false);
            return session == null ? null : session.getId();
        }
    }

    static ResponseEntity<?> unavailable() {
        return BffControllers.problem(HttpStatus.NOT_IMPLEMENTED,
                "Session listing unavailable: set spring.session.data.redis.repository-type=indexed");
    }
}
