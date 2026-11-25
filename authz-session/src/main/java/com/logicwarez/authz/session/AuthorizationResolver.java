package com.logicwarez.authz.session;

import java.util.List;

/**
 * Risolve ruoli e permessi di un utente al login e al cambio di tenant. Implementato in-process da
 * {@code authz-rbac}; un'applicazione puo' fornirne uno proprio (per esempio un client verso un servizio remoto).
 */
public interface AuthorizationResolver {

    /**
     * @param requestedTenant tenant scelto dall'utente, null se non indicato: il resolver ne sceglie uno
     *                        (per esempio l'ultimo usato) senza chiedere
     * @throws UserNotAuthorizedException       utente inesistente, disattivato o senza ruoli (sul tenant richiesto)
     * @throws TenantSelectionRequiredException il resolver non sa scegliere il tenant (resolver applicativi)
     */
    Resolved resolve(String username, String requestedTenant);

    /**
     * Come {@link #resolve(String, String)}, con un ruolo operativo preferito (ADR-28 di Quadrava): il resolver lo
     * attiva se l'utente lo ha sul tenant, altrimenti ne sceglie uno (per esempio l'ultimo usato) senza chiedere.
     * L'implementazione predefinita ignora il ruolo: resolver senza ruoli operativi.
     *
     * @param preferredRole ruolo operativo scelto dall'utente, null se non indicato
     */
    default Resolved resolve(String username, String requestedTenant, String preferredRole) {
        return resolve(username, requestedTenant);
    }

    /**
     * Come {@link #resolve}, per una richiesta con un token (accesso senza sessione, ripetuto a ogni richiesta): senza
     * effetti, in particolare senza cambiare il tenant con cui l'utente entrera' al prossimo login. L'implementazione
     * predefinita chiama {@link #resolve}.
     */
    default Resolved resolveForToken(String username, String requestedTenant) {
        return resolve(username, requestedTenant);
    }

    /**
     * @param tenants          tenant su cui l'utente puo' lavorare, compreso {@code tenantId}; vuoto se
     *                         l'applicazione non gestisce i tenant (il BFF non offre allora il cambio)
     * @param operationalRoles ruoli operativi dell'utente sul tenant, uno alla volta; vuoto se non ne ha (il BFF non
     *                         offre allora il cambio di ruolo e i permessi sono quelli di tutti i ruoli)
     * @param currentRole      ruolo operativo attivo, tra {@code operationalRoles}: i permessi sono quelli dei ruoli
     *                         di base piu' questo. Null senza ruoli operativi
     */
    record Resolved(String username, String email, String tenantId, List<SessionContext.Tenant> tenants,
                    List<String> roles, List<String> permissions, List<SessionContext.Role> operationalRoles,
                    String currentRole) {

        public Resolved {
            tenants = tenants == null ? List.of() : List.copyOf(tenants);
            operationalRoles = operationalRoles == null ? List.of() : List.copyOf(operationalRoles);
        }

        /** Senza ruoli operativi. */
        public Resolved(String username, String email, String tenantId, List<SessionContext.Tenant> tenants,
                        List<String> roles, List<String> permissions) {
            this(username, email, tenantId, tenants, roles, permissions, List.of(), null);
        }

        /** Senza elenco dei tenant (cambio di tenant non offerto). */
        public Resolved(String username, String email, String tenantId, List<String> roles, List<String> permissions) {
            this(username, email, tenantId, List.of(), roles, permissions);
        }
    }
}
