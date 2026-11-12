package com.logicwarez.authz.rbac.service;

import com.logicwarez.authz.session.UserNotAuthorizedException;
import com.logicwarez.authz.rbac.repository.AuthorizationRepository;
import com.logicwarez.authz.rbac.repository.AuthorizationRepository.ActiveUser;
import com.logicwarez.authz.rbac.repository.AuthorizationRepository.GrantRow;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

@Service
public class AuthorizationService {

    private final AuthorizationRepository repository;

    public AuthorizationService(AuthorizationRepository repository) {
        this.repository = repository;
    }

    /**
     * Risolve ruoli e permessi dell'utente e ricorda il tenant scelto per il login successivo.
     * Regola di scelta del tenant: tenant richiesto (se l'utente vi ha ruoli), altrimenti l'ultimo usato,
     * altrimenti il primo in ordine di codice. Il login non chiede mai il tenant: si cambia dopo (POST /bff/tenant).
     */
    @Transactional
    public AuthorizationContext resolve(String username, String requestedTenant) {
        return resolve(username, requestedTenant, true);
    }

    /**
     * @param remember ricordare il tenant per il login successivo; false per le richieste con un token, che si
     *                 risolvono a ogni chiamata e non cambiano il tenant con cui l'utente entra dal browser
     */
    @Transactional
    public AuthorizationContext resolve(String username, String requestedTenant, boolean remember) {
        ActiveUser user = repository.findActiveUser(username)
                .orElseThrow(() -> new UserNotAuthorizedException("Utente non trovato o non attivo"));

        List<GrantRow> grants = repository.findGrants(user.id());
        SortedMap<String, String> tenants = new TreeMap<>();
        for (GrantRow grant : grants) {
            String label = grant.tenantLabel() == null || grant.tenantLabel().isBlank()
                    ? grant.tenantId() : grant.tenantLabel();
            tenants.putIfAbsent(grant.tenantId(), label);
        }

        if (tenants.isEmpty()) {
            throw new UserNotAuthorizedException("Nessun ruolo assegnato");
        }

        String tenant = selectTenant(requestedTenant, user.lastTenantId(), tenants);
        if (remember) {
            repository.updateLastTenant(user.id(), tenant);
        }

        SortedSet<String> roles = new TreeSet<>();
        SortedSet<String> permissions = new TreeSet<>();
        for (GrantRow grant : grants) {
            if (grant.tenantId().equals(tenant)) {
                roles.add(grant.roleCode());
                if (grant.permissionCode() != null) {
                    permissions.add(grant.permissionCode());
                }
            }
        }

        return new AuthorizationContext(user.username(), user.email(), tenant,
                Collections.unmodifiableSortedSet(roles),
                Collections.unmodifiableSortedSet(permissions),
                Collections.unmodifiableSortedMap(tenants));
    }

    private static String selectTenant(String requestedTenant, String lastTenant, SortedMap<String, String> tenants) {
        if (requestedTenant != null && !requestedTenant.isBlank()) {
            if (!tenants.containsKey(requestedTenant)) {
                throw new UserNotAuthorizedException("Nessun ruolo sul tenant richiesto");
            }
            return requestedTenant;
        }
        if (lastTenant != null && tenants.containsKey(lastTenant)) {
            return lastTenant;
        }
        return tenants.firstKey();
    }
}
