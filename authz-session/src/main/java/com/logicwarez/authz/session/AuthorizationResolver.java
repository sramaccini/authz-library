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
     * Come {@link #resolve}, per una richiesta con un token (accesso senza sessione, ripetuto a ogni richiesta): senza
     * effetti, in particolare senza cambiare il tenant con cui l'utente entrera' al prossimo login. L'implementazione
     * predefinita chiama {@link #resolve}.
     */
    default Resolved resolveForToken(String username, String requestedTenant) {
        return resolve(username, requestedTenant);
    }

    /**
     * @param tenants tenant su cui l'utente puo' lavorare, compreso {@code tenantId}; vuoto se l'applicazione
     *                non gestisce i tenant (il BFF non offre allora il cambio)
     */
    record Resolved(String username, String email, String tenantId, List<SessionContext.Tenant> tenants,
                    List<String> roles, List<String> permissions) {

        public Resolved {
            tenants = tenants == null ? List.of() : List.copyOf(tenants);
        }

        /** Senza elenco dei tenant (cambio di tenant non offerto). */
        public Resolved(String username, String email, String tenantId, List<String> roles, List<String> permissions) {
            this(username, email, tenantId, List.of(), roles, permissions);
        }
    }
}
