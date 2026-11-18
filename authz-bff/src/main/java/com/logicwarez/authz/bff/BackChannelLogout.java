package com.logicwarez.authz.bff;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * OIDC Back-Channel Logout 1.0 ({@code authz.bff.backchannel-logout.enabled}): lo IAM chiama
 * {@code POST /bff/backchannel-logout} con un logout token quando una sua sessione finisce (logout da un'altra
 * applicazione, "esci dagli altri dispositivi" al cambio della password, sessione chiusa da un amministratore dello
 * IAM) e il BFF chiude le sessioni collegate: quelle con lo stesso {@code sid}, o tutte quelle del {@code sub} se il
 * token non ha {@code sid}. Al login il BFF ricorda su Redis a quale utente appartengono {@code sid} e {@code sub}.
 */
public final class BackChannelLogout {

    public static final String PATH = "/bff/backchannel-logout";
    static final String EVENT = "http://schemas.openid.net/event/backchannel-logout";

    private BackChannelLogout() {
    }

    /**
     * Validazione del logout token oltre alla firma: emittente, destinatario (il client del BFF), scadenza, evento
     * di back-channel logout, {@code iat} e {@code jti} presenti, {@code sub} o {@code sid}, nessun {@code nonce}.
     */
    public static OAuth2TokenValidator<Jwt> validator(String issuer, String clientId) {
        JwtTypeValidator type = new JwtTypeValidator("JWT", "logout+jwt");
        type.setAllowEmpty(true);
        OAuth2TokenValidator<Jwt> claims = token -> {
            String problem = null;
            if (token.getAudience() == null || !token.getAudience().contains(clientId)) {
                problem = "Logout token for another client";
            } else if (token.getIssuedAt() == null || token.getId() == null) {
                problem = "Logout token without iat or jti";
            } else if (!(token.getClaim("events") instanceof Map<?, ?> events) || !events.containsKey(EVENT)) {
                problem = "Not a back-channel logout token";
            } else if (token.hasClaim("nonce")) {
                problem = "Logout token with nonce";
            } else if (token.getSubject() == null && token.getClaimAsString("sid") == null) {
                problem = "Logout token without sub and sid";
            }
            return problem == null ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", problem, null));
        };
        return new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(), new JwtIssuerValidator(issuer), type,
                claims);
    }

    /** Da {@code sid} e {@code sub} dello IAM all'utente delle sessioni, su Redis fino alla scadenza assoluta. */
    public static class SessionIndex {

        private static final Duration REPLAY_WINDOW = Duration.ofMinutes(10);

        private final StringRedisTemplate redis;
        private final String prefix;
        private final Duration ttl;

        public SessionIndex(StringRedisTemplate redis, String prefix, Duration ttl) {
            this.redis = redis;
            this.prefix = prefix;
            this.ttl = ttl;
        }

        void remember(String sid, String sub, String username) {
            if (sid != null) {
                redis.opsForValue().set(prefix + "sid:" + sid, username, ttl);
            }
            if (sub != null) {
                redis.opsForValue().set(prefix + "sub:" + sub, username, ttl);
            }
        }

        String username(String sid, String sub) {
            String username = sid == null ? null : redis.opsForValue().get(prefix + "sid:" + sid);
            return username != null || sub == null ? username : redis.opsForValue().get(prefix + "sub:" + sub);
        }

        /** Vero la prima volta che si vede il jti: un logout token non si usa due volte. */
        boolean firstUse(String jti) {
            return Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(prefix + "jti:" + jti, "1", REPLAY_WINDOW));
        }
    }

    @RestController
    public static class BackChannelLogoutController {

        private static final Logger log = LoggerFactory.getLogger(BackChannelLogoutController.class);

        private final JwtDecoder decoder;
        private final SessionIndex index;
        private final ObjectProvider<FindByIndexNameSessionRepository<? extends Session>> sessions;

        public BackChannelLogoutController(JwtDecoder decoder, SessionIndex index,
                                           ObjectProvider<FindByIndexNameSessionRepository<? extends Session>> sessions) {
            this.decoder = decoder;
            this.index = index;
            this.sessions = sessions;
        }

        @PostMapping(path = PATH, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        public ResponseEntity<?> logout(@RequestParam(name = "logout_token", required = false) String logoutToken) {
            if (logoutToken == null || logoutToken.isBlank()) {
                return error(HttpStatus.BAD_REQUEST, "Missing logout_token");
            }
            FindByIndexNameSessionRepository<? extends Session> repository = sessions.getIfAvailable();
            if (repository == null) {
                return error(HttpStatus.NOT_IMPLEMENTED, "Back-channel logout needs repository-type=indexed");
            }
            Jwt token;
            try {
                token = decoder.decode(logoutToken);
            } catch (JwtException e) {
                log.info("Logout token rifiutato: {}", e.getMessage());
                return error(HttpStatus.BAD_REQUEST, "Invalid logout token");
            }
            String sid = token.getClaimAsString("sid");
            String sub = token.getSubject();
            try {
                if (!index.firstUse(token.getId())) {
                    return error(HttpStatus.BAD_REQUEST, "Logout token already used");
                }
                String username = index.username(sid, sub);
                int ended = 0;
                if (username != null) {
                    for (Map.Entry<String, ? extends Session> entry : repository.findByPrincipalName(username).entrySet()) {
                        Session session = entry.getValue();
                        boolean match = sid != null ? Objects.equals(sid, session.getAttribute(UserSessions.OIDC_SID))
                                : Objects.equals(sub, session.getAttribute(UserSessions.OIDC_SUB));
                        if (match) {
                            repository.deleteById(entry.getKey());
                            ended++;
                        }
                    }
                }
                log.info("Back-channel logout: utente={} sid={} sessioni chiuse={}", username, sid, ended);
            } catch (DataAccessException e) {
                log.error("Back-channel logout non eseguito: {}", e.toString());
                return error(HttpStatus.SERVICE_UNAVAILABLE, "Session store unavailable");
            }
            return ResponseEntity.ok().cacheControl(CacheControl.noStore()).build();
        }

        /** Risposta di errore di OIDC Back-Channel Logout (formato degli errori OAuth 2.0). */
        private static ResponseEntity<?> error(HttpStatus status, String description) {
            Map<String, String> body = new LinkedHashMap<>();
            body.put("error", "invalid_request");
            body.put("error_description", description);
            return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).body(body);
        }
    }
}
