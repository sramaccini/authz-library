package com.logicwarez.authz.rbac.service;

import java.util.Collections;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;

/**
 * Contesto di autorizzazione risolto per un utente su un tenant.
 *
 * @param availableTenants tenant su cui l'utente ha ruoli: codice -> etichetta da mostrare
 * @param operationalRoles ruoli operativi dell'utente sul tenant: codice -> etichetta da mostrare; vuoto se non ne ha
 * @param currentRole      ruolo operativo attivo, null senza ruoli operativi: {@code permissions} sono quelli dei
 *                         ruoli di base piu' questo
 */
public record AuthorizationContext(
        String username,
        String email,
        String tenantId,
        SortedSet<String> roles,
        SortedSet<String> permissions,
        SortedMap<String, String> availableTenants,
        SortedMap<String, String> operationalRoles,
        String currentRole) {

    public AuthorizationContext {
        operationalRoles = operationalRoles == null
                ? Collections.unmodifiableSortedMap(new TreeMap<>()) : operationalRoles;
    }

    /** Senza ruoli operativi. */
    public AuthorizationContext(String username, String email, String tenantId, SortedSet<String> roles,
                                SortedSet<String> permissions, SortedMap<String, String> availableTenants) {
        this(username, email, tenantId, roles, permissions, availableTenants, null, null);
    }
}
