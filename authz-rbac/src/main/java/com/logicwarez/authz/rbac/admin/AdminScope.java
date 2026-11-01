package com.logicwarez.authz.rbac.admin;

import com.logicwarez.authz.session.SessionContext;

import java.util.Set;

/**
 * Ambito dell'amministratore, ricavato dalla sessione del BFF.
 * - authz.rbac.manage       -> amministratore delegato: solo il tenant della propria sessione;
 * - authz.rbac.manageglobal -> amministratore globale: tutti i tenant, definizione di ruoli e tenant, stato utenti.
 */
public record AdminScope(String username, String tenantId, Set<String> permissions) {

    public static final String MANAGE = "authz.rbac.manage";
    public static final String MANAGE_GLOBAL = "authz.rbac.manageglobal";

    public static AdminScope of(SessionContext session) {
        return new AdminScope(session.username(), session.tenantId(), Set.copyOf(session.permissions()));
    }

    public boolean isGlobal() {
        return permissions.contains(MANAGE_GLOBAL);
    }

    public boolean canManageTenant(String tenant) {
        return isGlobal() || (permissions.contains(MANAGE) && tenantId.equals(tenant));
    }

    void requireGlobal() {
        if (!isGlobal()) {
            throw AdminProblem.forbidden("global-admin-required", "Operation reserved to the global administrator");
        }
    }

    void requireTenant(String tenant) {
        if (!canManageTenant(tenant)) {
            throw AdminProblem.forbidden("tenant-out-of-scope", "Tenant outside the administrator's scope");
        }
    }

    void requireNotSelf(String targetUsername) {
        if (username.equals(targetUsername)) {
            throw AdminProblem.forbidden("self-modification", "Administrators cannot modify their own account");
        }
    }
}
