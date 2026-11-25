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
 * @param operationalRoles ruoli operativi che l'utente puo' scegliere, uno alla volta (ADR-28 di Quadrava); vuoto
 *                  se l'utente non ne ha: i permessi sono allora quelli di tutti i suoi ruoli
 * @param currentRole ruolo operativo attivo: i permessi sono quelli dei ruoli di base piu' questo; null senza ruoli
 *                  operativi
 */
public record SessionContext(String username,
                             String name,
                             String email,
                             String tenantId,
                             List<Tenant> tenants,
                             List<String> roles,
                             List<String> permissions,
                             Instant createdAt,
                             Instant expiresAt,
                             List<Role> operationalRoles,
                             String currentRole) implements Serializable {

    // Invariato con i ruoli operativi: un record si deserializza per nome dei campi, e quelli assenti in una sessione
    // scritta dalla versione precedente valgono null (nessun ruolo operativo).
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
        operationalRoles = operationalRoles == null ? List.of() : List.copyOf(operationalRoles);
    }

    /** Senza ruoli operativi. */
    public SessionContext(String username, String name, String email, String tenantId, List<Tenant> tenants,
                          List<String> roles, List<String> permissions, Instant createdAt, Instant expiresAt) {
        this(username, name, email, tenantId, tenants, roles, permissions, createdAt, expiresAt, List.of(), null);
    }

    /** Ruolo operativo offerto all'utente: identificativo e nome da mostrare. */
    public record Role(String id, String label) implements Serializable {

        @Serial
        private static final long serialVersionUID = 1L;
    }

    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }

    public boolean offersTenant(String tenant) {
        return tenants.stream().anyMatch(t -> t.id().equals(tenant));
    }

    public boolean offersRole(String role) {
        return operationalRoles.stream().anyMatch(r -> r.id().equals(role));
    }

    public boolean isExpiredAt(Instant now) {
        return expiresAt != null && !now.isBefore(expiresAt);
    }

    /**
     * Versione dei permessi (header X-Permissions-Version del contratto di Quadrava): cambia quando cambiano
     * i permessi, per esempio dopo un cambio di tenant, o il ruolo operativo; uguale per insiemi uguali.
     */
    public String permissionsVersion() {
        return versionOf(permissions, currentRole);
    }

    /** Versione di un insieme di permessi, senza ruolo operativo. */
    public static String versionOf(Collection<String> permissions) {
        return versionOf(permissions, null);
    }

    /**
     * Versione di un insieme di permessi con il ruolo operativo attivo (stessa regola di
     * {@link #permissionsVersion()}): due ruoli con gli stessi permessi danno versioni diverse, cosi' la UI vede il
     * cambio. Senza ruolo e' quella di sempre.
     */
    public static String versionOf(Collection<String> permissions, String role) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String joined = String.join("\n", permissions.stream().sorted().distinct().toList());
            if (role != null) {
                joined = "role:" + role + "\n" + joined;
            }
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
