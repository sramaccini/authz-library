package com.logicwarez.authz.bff;

import java.util.List;
import java.util.Optional;
import java.util.SortedSet;
import java.util.TreeSet;

import com.logicwarez.authz.session.PermissionContributor;
import com.logicwarez.authz.session.SessionContext;

/**
 * Permessi visti dalla UI: quelli della sessione piu' quelli dei {@link PermissionContributor} dell'applicazione.
 * Stessa regola per {@code /authz/capabilities}, {@code /authz/check} e l'header {@code X-Permissions-Version}, cosi'
 * la versione resta coerente con l'elenco.
 */
public class EffectivePermissions {

    private final List<PermissionContributor> contributors;

    public EffectivePermissions(List<PermissionContributor> contributors) {
        this.contributors = List.copyOf(contributors);
    }

    public SortedSet<String> of(SessionContext session) {
        SortedSet<String> permissions = new TreeSet<>(session.permissions());
        for (PermissionContributor contributor : contributors) {
            permissions.addAll(contributor.permissions(session));
        }
        return permissions;
    }

    public String version(SessionContext session) {
        return contributors.isEmpty() ? session.permissionsVersion()
                : SessionContext.versionOf(of(session), session.currentRole());
    }

    /** Controllo di un permesso, su una risorsa se indicata; {@code effective} e' il risultato di {@link #of}. */
    public boolean allows(SessionContext session, SortedSet<String> effective, String permission,
                          PermissionContributor.Resource resource) {
        if (resource != null) {
            for (PermissionContributor contributor : contributors) {
                Optional<Boolean> decision = contributor.check(session, permission, resource);
                if (decision.isPresent()) {
                    return decision.get();
                }
            }
        }
        return effective.contains(permission);
    }
}
