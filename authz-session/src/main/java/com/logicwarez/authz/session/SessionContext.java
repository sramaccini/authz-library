package com.logicwarez.authz.session;

import java.io.Serial;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * Contesto di sicurezza dell'utente, salvato come attributo della sessione HTTP (Spring Session su Redis)
 * al termine del login. Sostituisce il payload {@code session:<SESSION_ID>} scritto a mano dal vecchio BFF.
 *
 * @param name      nome completo da mostrare (claim "name" dello IAM), null se assente
 * @param tenants   tenant su cui l'utente puo' lavorare, compreso quello della sessione; vuoto se non gestiti
 * @param expiresAt scadenza assoluta: la sessione scade per inattivita' (timeout standard di Spring Session)
 *                  oppure a questa data, anche se l'utente resta attivo
 */
public record SessionContext(String username,
                             String name,
                             String email,
                             String tenantId,
                             List<Tenant> tenants,
                             List<String> roles,
                             List<String> permissions,
                             Instant createdAt,
                             Instant expiresAt) implements Serializable {

    @Serial
    private static final long serialVersionUID = 2L;

    /** Nome dell'attributo di sessione che contiene il contesto. */
    public static final String ATTRIBUTE = SessionContext.class.getName();

    /** Tenant offerto all'utente: identificativo e nome da mostrare. */
    public record Tenant(String id, String label) implements Serializable {

        @Serial
        private static final long serialVersionUID = 1L;
    }

    public SessionContext {
        tenants = tenants == null ? List.of() : List.copyOf(tenants);
        roles = roles == null ? List.of() : List.copyOf(roles);
        permissions = permissions == null ? List.of() : List.copyOf(permissions);
    }

    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }

    public boolean offersTenant(String tenant) {
        return tenants.stream().anyMatch(t -> t.id().equals(tenant));
    }

    public boolean isExpiredAt(Instant now) {
        return expiresAt != null && !now.isBefore(expiresAt);
    }

    /**
     * Versione dei permessi (header X-Permissions-Version del contratto di Quadrava): cambia quando cambiano
     * i permessi, per esempio dopo un cambio di tenant; uguale per insiemi uguali.
     */
    public String permissionsVersion() {
        return versionOf(permissions);
    }

    /** Versione di un insieme di permessi (stessa regola di {@link #permissionsVersion()}). */
    public static String versionOf(Collection<String> permissions) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String joined = String.join("\n", permissions.stream().sorted().distinct().toList());
            return HexFormat.of().formatHex(digest.digest(joined.getBytes(StandardCharsets.UTF_8)), 0, 8);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Contesto della sessione corrente, senza crearne una nuova. */
    public static Optional<SessionContext> from(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session == null ? Optional.empty() : from(session);
    }

    public static Optional<SessionContext> from(HttpSession session) {
        return session.getAttribute(ATTRIBUTE) instanceof SessionContext context
                ? Optional.of(context) : Optional.empty();
    }
}
