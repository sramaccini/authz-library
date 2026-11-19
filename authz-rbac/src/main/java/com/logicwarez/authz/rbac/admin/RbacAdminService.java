package com.logicwarez.authz.rbac.admin;

import com.logicwarez.authz.rbac.admin.AdminApi.AuditEntry;
import com.logicwarez.authz.rbac.admin.AdminApi.ForgetResult;
import com.logicwarez.authz.rbac.admin.AdminApi.PermissionView;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleAssignmentRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleCreateRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleUpdateRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleView;
import com.logicwarez.authz.rbac.admin.AdminApi.TenantCreateRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.TenantUserView;
import com.logicwarez.authz.rbac.admin.AdminApi.TenantView;
import com.logicwarez.authz.rbac.admin.AdminApi.UserCreateRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.UserUpdateRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.UserView;
import com.logicwarez.authz.rbac.admin.RbacAdminRepository.UserRow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Amministrazione RBAC con le regole di sicurezza:
 * - l'amministratore delegato opera solo sul tenant della propria sessione;
 * - ruoli, tenant e stato degli utenti sono riservati all'amministratore globale (valgono per tutti i tenant);
 * - i permessi con azione "...global" stanno solo nei ruoli di sistema e un amministratore delegato non puo' assegnare
 *   ne' togliere ruoli che li contengono: nessuna promozione ad amministratore globale;
 * - nessuno modifica la propria utenza: insieme alla regola precedente garantisce che resti sempre
 *   almeno un amministratore globale;
 * - ogni modifica e' registrata in rbac_audit nella stessa transazione.
 * Le modifiche hanno effetto al login successivo degli utenti coinvolti (ruoli e permessi sono copiati
 * nella sessione al login); per un effetto immediato si revocano le sessioni tramite il BFF.
 */
@Service
public class RbacAdminService {

    private static final Logger log = LoggerFactory.getLogger(RbacAdminService.class);
    /** Azione dei permessi riservati a GLOBAL_ADMIN (authz.rbac.manageglobal, authz.session.revokeglobal). */
    private static final String GLOBAL_SUFFIX = "global";
    private static final int MAX_PAGE = 200;

    private final RbacAdminRepository repository;
    private final JsonMapper json;

    public RbacAdminService(RbacAdminRepository repository, JsonMapper json) {
        this.repository = repository;
        this.json = json;
    }

    // --- Catalogo e ruoli ---

    @Transactional(readOnly = true)
    public List<PermissionView> permissions() {
        return repository.listPermissions();
    }

    @Transactional(readOnly = true)
    public List<RoleView> roles() {
        return repository.listRoles();
    }

    @Transactional
    public RoleView createRole(AdminScope actor, RoleCreateRequest request) {
        actor.requireGlobal();
        if (repository.findRole(request.code()).isPresent()) {
            throw AdminProblem.conflict("role-exists", "Role already exists");
        }
        Set<String> permissions = validatePermissions(request.permissions());
        repository.insertRole(request.code(), request.description());
        repository.replaceRolePermissions(request.code(), permissions);
        RoleView created = repository.findRole(request.code()).orElseThrow();
        audit(actor, "ROLE_CREATED", "ROLE", request.code(), null, null, created);
        return created;
    }

    @Transactional
    public RoleView updateRole(AdminScope actor, String code, RoleUpdateRequest request) {
        actor.requireGlobal();
        RoleView before = existingCustomRole(code);
        Set<String> permissions = validatePermissions(request.permissions());
        if (!repository.updateRole(code, request.description(), request.version())) {
            throw AdminProblem.conflict("version-mismatch",
                    "The role was changed by another administrator: reload and retry");
        }
        repository.replaceRolePermissions(code, permissions);
        RoleView after = repository.findRole(code).orElseThrow();
        audit(actor, "ROLE_UPDATED", "ROLE", code, null, before, after);
        return after;
    }

    @Transactional
    public void deleteRole(AdminScope actor, String code) {
        actor.requireGlobal();
        RoleView before = existingCustomRole(code);
        if (repository.isRoleAssigned(code)) {
            throw AdminProblem.conflict("role-assigned", "Role still assigned: remove the assignments first");
        }
        repository.deleteRole(code);
        audit(actor, "ROLE_DELETED", "ROLE", code, null, before, null);
    }

    // --- Tenant ---

    @Transactional(readOnly = true)
    public List<TenantView> tenants(AdminScope actor) {
        return repository.listTenants().stream()
                .filter(t -> actor.canManageTenant(t.code()))
                .toList();
    }

    @Transactional
    public TenantView createTenant(AdminScope actor, TenantCreateRequest request) {
        actor.requireGlobal();
        if (repository.findTenant(request.code()).isPresent()) {
            throw AdminProblem.conflict("tenant-exists", "Tenant already exists");
        }
        repository.insertTenant(request.code(), request.description());
        TenantView created = new TenantView(request.code(), request.description());
        audit(actor, "TENANT_CREATED", "TENANT", request.code(), request.code(), null, created);
        return created;
    }

    @Transactional(readOnly = true)
    public List<TenantUserView> tenantUsers(AdminScope actor, String tenant, int limit, int offset) {
        actor.requireTenant(tenant);
        existingTenant(tenant);
        return repository.tenantUsers(tenant, Math.clamp(limit, 1, MAX_PAGE), Math.max(offset, 0));
    }

    // --- Utenti ---

    @Transactional(readOnly = true)
    public UserView user(AdminScope actor, String username) {
        return view(actor, existingUser(username));
    }

    @Transactional
    public UserView createUser(AdminScope actor, UserCreateRequest request) {
        if (repository.findUser(request.username()).isPresent()) {
            throw AdminProblem.conflict("user-exists", "User already exists");
        }
        repository.insertUser(request.username(), request.email());
        UserView created = view(actor, existingUser(request.username()));
        audit(actor, "USER_CREATED", "USER", request.username(), actor.tenantId(), null, created);
        return created;
    }

    @Transactional
    public UserView updateUser(AdminScope actor, String username, UserUpdateRequest request) {
        actor.requireGlobal();
        actor.requireNotSelf(username);
        UserRow before = existingUser(username);
        boolean active = request.active() != null ? request.active() : before.active();
        String email = request.email() != null ? request.email() : before.email();
        repository.updateUser(username, active, email);
        UserRow after = existingUser(username);
        audit(actor, "USER_UPDATED", "USER", username, null,
                Map.of("active", before.active(), "email", String.valueOf(before.email())),
                Map.of("active", after.active(), "email", String.valueOf(after.email())));
        return view(actor, after);
    }

    /** Sostituisce i ruoli dell'utente su un tenant (lista vuota = nessun ruolo su quel tenant). */
    @Transactional
    public UserView replaceUserRoles(AdminScope actor, String tenant, String username, RoleAssignmentRequest request) {
        actor.requireTenant(tenant);
        actor.requireNotSelf(username);
        if (!repository.lockTenant(tenant)) {
            throw AdminProblem.notFound("Unknown tenant");
        }
        UserRow user = existingUser(username);
        SortedSet<String> before = repository.userAssignments(user.id()).getOrDefault(tenant, new TreeSet<>());
        SortedSet<String> after = new TreeSet<>(request.roles());

        Set<String> touched = new HashSet<>(before);
        touched.addAll(after);
        Map<String, SortedSet<String>> permissionsByRole = repository.rolePermissions(touched);
        Set<String> unknown = new TreeSet<>(after);
        unknown.removeAll(permissionsByRole.keySet());
        if (!unknown.isEmpty()) {
            throw AdminProblem.invalid("unknown-role", "Unknown roles: " + unknown);
        }
        if (!actor.isGlobal()) {
            Set<String> changed = new HashSet<>(touched);
            changed.removeAll(intersection(before, after));
            boolean escalation = changed.stream()
                    .anyMatch(role -> permissionsByRole.getOrDefault(role, new TreeSet<>()).stream()
                            .anyMatch(p -> p.endsWith(GLOBAL_SUFFIX)));
            if (escalation) {
                throw AdminProblem.forbidden("global-role",
                        "Roles with global permissions can be managed only by the global administrator");
            }
        }

        repository.replaceUserRoles(user.id(), tenant, after);
        audit(actor, "USER_ROLES_REPLACED", "USER", username, tenant,
                Map.of("roles", before), Map.of("roles", after));
        return view(actor, user);
    }

    /**
     * L'utente, se esiste, con le assegnazioni visibili all'amministratore. A differenza di {@link #user} non lancia
     * eccezioni per un utente sconosciuto: dentro la transazione del chiamante non la segna rollback-only.
     */
    @Transactional(readOnly = true)
    public Optional<UserView> findUser(AdminScope actor, String username) {
        return repository.findUser(username).map(user -> view(actor, user));
    }

    /**
     * Toglie il nome dell'utente dal tenant (pseudonimizzazione, ASVS 8.3.2), dopo che l'applicazione gli ha tolto i
     * ruoli ({@link #replaceUserRoles} con lista vuota), nella stessa transazione:
     * <ul>
     *   <li>nelle voci di audit del tenant il nome diventa {@code pseudonym} in autore, oggetto e valori JSON;</li>
     *   <li>se l'utente non ha piu' ruoli su nessun tenant la sua riga (email, token personali) viene eliminata e il nome
     *       sparisce anche dalle voci di audit senza tenant (token, attivazione); un amministratore delegato non
     *       elimina un utente disattivato dall'amministratore globale (la riga resta, {@code userDeleted} false);</li>
     *   <li>una voce USER_FORGOTTEN con il solo pseudonimo.</li>
     * </ul>
     * Regole di replaceUserRoles: tenant dell'amministratore, mai se stessi; l'utente non deve avere ruoli sul tenant
     * (quindi nemmeno ruoli con permessi globali). Si puo' ripetere: con l'utente gia' eliminato aggiorna solo l'audit.
     */
    @Transactional
    public ForgetResult forgetUser(AdminScope actor, String tenant, String username, String pseudonym) {
        actor.requireTenant(tenant);
        actor.requireNotSelf(username);
        if (pseudonym == null || !pseudonym.matches(AdminApi.USERNAME) || pseudonym.equals(username)) {
            throw AdminProblem.invalid("invalid-pseudonym", "The pseudonym must be a valid username other than the user's");
        }
        if (!repository.lockTenant(tenant)) {
            throw AdminProblem.notFound("Unknown tenant");
        }
        if (repository.findUser(pseudonym).isPresent()) {
            throw AdminProblem.conflict("pseudonym-exists", "The pseudonym is the username of an existing user");
        }
        Optional<UserRow> user = repository.findUser(username);
        if (user.isPresent() && repository.userAssignments(user.get().id()).containsKey(tenant)) {
            throw AdminProblem.conflict("user-has-roles", "Remove the user's roles on the tenant first");
        }
        boolean delete = user.isPresent() && !repository.hasAnyRole(user.get().id())
                && (actor.isGlobal() || user.get().active());
        String quoted = json.writeValueAsString(username);
        int entries = 0;
        for (RbacAdminRepository.AuditRow row : repository.auditMentioning(tenant, delete, username, quoted)) {
            repository.updateAudit(new RbacAdminRepository.AuditRow(row.id(),
                    username.equals(row.actor()) ? pseudonym : row.actor(),
                    username.equals(row.target()) ? pseudonym : row.target(),
                    pseudonymize(row.beforeState(), username, pseudonym),
                    pseudonymize(row.afterState(), username, pseudonym)));
            entries++;
        }
        if (delete) {
            repository.deleteUser(user.get().id());
        }
        ForgetResult result = new ForgetResult(pseudonym, tenant, entries, delete);
        audit(actor, "USER_FORGOTTEN", "USER", pseudonym, tenant, null, result);
        return result;
    }

    /** Lo stato JSON con ogni stringa uguale al nome sostituita dallo pseudonimo (anche dentro liste e oggetti). */
    private String pseudonymize(String state, String username, String pseudonym) {
        if (state == null) {
            return null;
        }
        return json.writeValueAsString(replaceStrings(json.readTree(state), username, pseudonym));
    }

    private JsonNode replaceStrings(JsonNode node, String from, String to) {
        if (node.isString()) {
            return from.equals(node.asString()) ? json.getNodeFactory().stringNode(to) : node;
        }
        if (node instanceof ObjectNode object) {
            for (Map.Entry<String, JsonNode> property : List.copyOf(object.properties())) {
                object.replace(property.getKey(), replaceStrings(property.getValue(), from, to));
            }
        } else if (node instanceof ArrayNode array) {
            for (int i = 0; i < array.size(); i++) {
                array.set(i, replaceStrings(array.get(i), from, to));
            }
        }
        return node;
    }

    // --- Audit ---

    @Transactional(readOnly = true)
    public List<AuditEntry> audit(AdminScope actor, String tenant, int limit, int offset) {
        String scope = tenant;
        if (!actor.isGlobal()) {
            scope = actor.tenantId(); // l'amministratore delegato vede solo il proprio tenant
        }
        return repository.listAudit(scope, Math.clamp(limit, 1, MAX_PAGE), Math.max(offset, 0));
    }

    // --- Supporto ---

    private UserView view(AdminScope actor, UserRow user) {
        SortedMap<String, SortedSet<String>> visible = new TreeMap<>();
        repository.userAssignments(user.id()).forEach((tenant, roles) -> {
            if (actor.canManageTenant(tenant)) {
                visible.put(tenant, roles);
            }
        });
        return new UserView(user.username(), user.email(), user.active(), visible);
    }

    private UserRow existingUser(String username) {
        return repository.findUser(username).orElseThrow(() -> AdminProblem.notFound("Unknown user"));
    }

    private void existingTenant(String tenant) {
        repository.findTenant(tenant).orElseThrow(() -> AdminProblem.notFound("Unknown tenant"));
    }

    private RoleView existingCustomRole(String code) {
        RoleView role = repository.findRole(code).orElseThrow(() -> AdminProblem.notFound("Unknown role"));
        if (role.system()) {
            throw AdminProblem.forbidden("system-role",
                    "System role: it changes only through database migrations");
        }
        return role;
    }

    /** Permessi esistenti nel catalogo e non riservati ai ruoli di sistema. */
    private Set<String> validatePermissions(List<String> requested) {
        Set<String> permissions = new TreeSet<>(requested);
        Set<String> global = new TreeSet<>();
        permissions.stream().filter(p -> p.endsWith(GLOBAL_SUFFIX)).forEach(global::add);
        if (!global.isEmpty()) {
            throw AdminProblem.invalid("global-permission",
                    "Global permissions are reserved to the system role GLOBAL_ADMIN: " + global);
        }
        Set<String> unknown = new TreeSet<>(permissions);
        unknown.removeAll(repository.existingPermissions(permissions));
        if (!unknown.isEmpty()) {
            throw AdminProblem.invalid("unknown-permission", "Permissions not in the catalog: " + unknown);
        }
        return permissions;
    }

    private void audit(AdminScope actor, String action, String targetType, String target, String tenantId,
                       Object before, Object after) {
        repository.insertAudit(actor, action, targetType, target, tenantId,
                before == null ? null : json.writeValueAsString(before),
                after == null ? null : json.writeValueAsString(after));
        log.info("Audit RBAC: azione={} amministratore={} oggetto={}:{} tenant={}",
                action, actor.username(), targetType, target, tenantId);
    }

    private static Set<String> intersection(Set<String> a, Set<String> b) {
        Set<String> result = new HashSet<>(a);
        result.retainAll(b);
        return result;
    }
}
