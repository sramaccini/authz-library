package com.logicwarez.authz.rbac.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.logicwarez.authz.rbac.RbacJdbc;
import com.logicwarez.authz.rbac.RbacProperties;
import com.logicwarez.authz.session.PersonalAccessTokenVerifier;
import org.springframework.transaction.annotation.Transactional;

/**
 * Token di accesso personali: creati, elencati e revocati dal loro utente, salvati solo come hash SHA-256 (il token ha
 * 256 bit casuali: un hash lento non serve), mostrati una volta. Il token vale con i permessi dell'utente, risolti a
 * ogni richiesta: un utente disattivato o senza ruoli non entra nemmeno con il token. Creazione e revoca vanno
 * nell'audit RBAC.
 */
public class PersonalAccessTokens implements PersonalAccessTokenVerifier {

    /** Durata di un token creato senza indicarla. */
    public static final int DEFAULT_DAYS = 90;

    /** last_used_at si aggiorna al piu' una volta in questo intervallo, per non scrivere a ogni richiesta. */
    private static final Duration LAST_USED_RESOLUTION = Duration.ofMinutes(1);

    private final RbacJdbc jdbc;
    private final RbacProperties.Tokens properties;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public PersonalAccessTokens(RbacJdbc jdbc, RbacProperties.Tokens properties, Clock clock) {
        this.jdbc = jdbc;
        this.properties = properties;
        this.clock = clock;
    }

    /** @param hint inizio del token, per riconoscerlo nell'elenco */
    public record TokenView(UUID id, String name, String hint, OffsetDateTime createdAt, OffsetDateTime expiresAt,
                            OffsetDateTime lastUsedAt) {
    }

    /** Il token in chiaro: c'e' solo nella risposta della creazione. */
    public record CreatedToken(UUID id, String name, String token, OffsetDateTime createdAt,
                               OffsetDateTime expiresAt) {
    }

    /** Errore di una richiesta sui token, con lo status HTTP da rispondere. */
    public static class TokenException extends RuntimeException {

        private final int status;

        TokenException(int status, String detail) {
            super(detail);
            this.status = status;
        }

        public int status() {
            return status;
        }
    }

    @Transactional
    public CreatedToken create(String username, String name, int days) {
        if (days < 1 || days > properties.maxDays()) {
            throw new TokenException(400, "Validity must be between 1 and " + properties.maxDays() + " days");
        }
        // FOR UPDATE: due creazioni concorrenti dello stesso utente non superano insieme il limite
        UUID userId = jdbc.sql("SELECT id FROM app_user WHERE username = :username AND is_active FOR UPDATE")
                .param("username", username).query(UUID.class).optional()
                .orElseThrow(() -> new TokenException(403, "User not active"));
        Instant now = clock.instant();
        long active = jdbc.sql("""
                        SELECT count(*) FROM personal_access_token
                         WHERE user_id = :userId AND revoked_at IS NULL AND expires_at > :now""")
                .param("userId", userId).param("now", at(now)).query(Long.class).single();
        if (active >= properties.maxPerUser()) {
            throw new TokenException(409, "Too many active tokens (at most " + properties.maxPerUser() + ")");
        }
        byte[] secret = new byte[32];
        random.nextBytes(secret);
        String token = PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
        UUID id = UUID.randomUUID();
        OffsetDateTime created = at(now);
        OffsetDateTime expires = at(now.plus(Duration.ofDays(days)));
        jdbc.sql("""
                        INSERT INTO personal_access_token (id, user_id, name, token_hash, token_hint, created_at, expires_at)
                        VALUES (:id, :userId, :name, :hash, :hint, :created, :expires)""")
                .param("id", id).param("userId", userId).param("name", name).param("hash", hash(token))
                .param("hint", token.substring(0, PREFIX.length() + 4)).param("created", created)
                .param("expires", expires).update();
        audit(username, "TOKEN_CREATED", id);
        return new CreatedToken(id, name, token, created, expires);
    }

    /** Token non revocati dell'utente, anche scaduti, piu' recenti prima. */
    @Transactional(readOnly = true)
    public List<TokenView> list(String username) {
        return jdbc.sql("""
                        SELECT t.id, t.name, t.token_hint AS hint, t.created_at, t.expires_at, t.last_used_at
                          FROM personal_access_token t
                          JOIN app_user u ON u.id = t.user_id
                         WHERE u.username = :username AND t.revoked_at IS NULL
                         ORDER BY t.created_at DESC""")
                .param("username", username).query(TokenView.class).list();
    }

    @Transactional
    public void revoke(String username, UUID id) {
        int revoked = jdbc.sql("""
                        UPDATE personal_access_token SET revoked_at = :now
                         WHERE id = :id AND revoked_at IS NULL
                           AND user_id = (SELECT u.id FROM app_user u WHERE u.username = :username)""")
                .param("now", at(clock.instant())).param("username", username).param("id", id).update();
        if (revoked == 0) {
            throw new TokenException(404, "Unknown token");
        }
        audit(username, "TOKEN_REVOKED", id);
    }

    @Override
    @Transactional
    public Optional<Owner> verify(String token) {
        if (token == null || !token.startsWith(PREFIX)) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        Optional<Row> row = jdbc.sql("""
                        SELECT t.id, u.username, t.expires_at, t.last_used_at
                          FROM personal_access_token t
                          JOIN app_user u ON u.id = t.user_id
                         WHERE t.token_hash = :hash AND t.revoked_at IS NULL AND t.expires_at > :now AND u.is_active""")
                .param("hash", hash(token)).param("now", at(now)).query(Row.class).optional();
        row.filter(r -> r.lastUsedAt() == null
                        || r.lastUsedAt().toInstant().isBefore(now.minus(LAST_USED_RESOLUTION)))
                .ifPresent(r -> jdbc.sql("UPDATE personal_access_token SET last_used_at = :now WHERE id = :id")
                        .param("now", at(now)).param("id", r.id()).update());
        return row.map(r -> new Owner(r.username(), r.expiresAt().toInstant()));
    }

    private record Row(UUID id, String username, OffsetDateTime expiresAt, OffsetDateTime lastUsedAt) {
    }

    private void audit(String username, String action, UUID id) {
        jdbc.sql("""
                        INSERT INTO rbac_audit (actor, action, target_type, target)
                        VALUES (:actor, :action, 'TOKEN', :target)""")
                .param("actor", username).param("action", action).param("target", id.toString()).update();
    }

    private static OffsetDateTime at(Instant instant) {
        return instant.atOffset(ZoneOffset.UTC);
    }

    static String hash(String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
