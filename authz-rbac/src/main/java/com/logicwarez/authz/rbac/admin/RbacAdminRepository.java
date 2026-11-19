package com.logicwarez.authz.rbac.admin;

import com.logicwarez.authz.rbac.admin.AdminApi.AuditEntry;
import com.logicwarez.authz.rbac.admin.AdminApi.PermissionView;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleView;
import com.logicwarez.authz.rbac.admin.AdminApi.TenantUserView;
import com.logicwarez.authz.rbac.admin.AdminApi.TenantView;
import com.logicwarez.authz.rbac.RbacJdbc;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Collectors;

/** Query e comandi del modello RBAC per l'amministrazione (JdbcClient, nessun ORM). */
@Repository
public class RbacAdminRepository {

    public record UserRow(UUID id, String username, String email, boolean active) {
    }

    record RoleRow(String code, String description, boolean system, int version, String permission) {
    }

    record TenantUserRow(String username, String email, boolean active, String role) {
    }

    private final RbacJdbc jdbc;

    public RbacAdminRepository(RbacJdbc jdbc) {
        this.jdbc = jdbc;
    }

    // --- Permessi (catalogo in sola lettura) ---

    public List<PermissionView> listPermissions() {
        return jdbc.sql("SELECT permission_code, description FROM app_permission ORDER BY permission_code")
                .query((rs, n) -> new PermissionView(rs.getString(1), rs.getString(2)))
                .list();
    }

    public Set<String> existingPermissions(Collection<String> codes) {
        if (codes.isEmpty()) {
            return Set.of();
        }
        return Set.copyOf(jdbc.sql("SELECT permission_code FROM app_permission WHERE permission_code IN (:codes)")
                .param("codes", codes)
                .query(String.class)
                .list());
    }

    // --- Ruoli ---

    private static final String SELECT_ROLES = """
            SELECT r.role_code, r.description, r.is_system, r.version, p.permission_code
              FROM app_role r
              LEFT JOIN role_permission rp ON rp.role_id = r.id
              LEFT JOIN app_permission p   ON p.id = rp.permission_id
            """;

    public List<RoleView> listRoles() {
        return toRoles(jdbc.sql(SELECT_ROLES + " ORDER BY r.role_code").query(this::roleRow).list());
    }

    public Optional<RoleView> findRole(String code) {
        return toRoles(jdbc.sql(SELECT_ROLES + " WHERE r.role_code = :code")
                .param("code", code)
                .query(this::roleRow)
                .list()).stream().findFirst();
    }

    /** Permessi dei ruoli richiesti; i codici inesistenti non compaiono nella mappa. */
    public Map<String, SortedSet<String>> rolePermissions(Collection<String> roleCodes) {
        if (roleCodes.isEmpty()) {
            return Map.of();
        }
        return toRoles(jdbc.sql(SELECT_ROLES + " WHERE r.role_code IN (:codes)")
                .param("codes", roleCodes)
                .query(this::roleRow)
                .list()).stream()
                .collect(Collectors.toMap(RoleView::code, RoleView::permissions));
    }

    public void insertRole(String code, String description) {
        jdbc.sql("INSERT INTO app_role (role_code, description) VALUES (:code, :description)")
                .param("code", code)
                .param("description", description)
                .update();
    }

    /** @return false se la version non corrisponde (modifica concorrente) */
    public boolean updateRole(String code, String description, int expectedVersion) {
        return jdbc.sql("""
                        UPDATE app_role SET description = :description, version = version + 1
                         WHERE role_code = :code AND version = :version
                        """)
                .param("code", code)
                .param("description", description)
                .param("version", expectedVersion)
                .update() == 1;
    }

    public void replaceRolePermissions(String code, Collection<String> permissions) {
        jdbc.sql("DELETE FROM role_permission WHERE role_id = (SELECT id FROM app_role WHERE role_code = :code)")
                .param("code", code)
                .update();
        if (!permissions.isEmpty()) {
            jdbc.sql("""
                            INSERT INTO role_permission (role_id, permission_id)
                            SELECT r.id, p.id FROM app_role r, app_permission p
                             WHERE r.role_code = :code AND p.permission_code IN (:permissions)
                            """)
                    .param("code", code)
                    .param("permissions", permissions)
                    .update();
        }
    }

    public boolean isRoleAssigned(String code) {
        return jdbc.sql("""
                        SELECT EXISTS (SELECT 1 FROM user_role ur JOIN app_role r ON r.id = ur.role_id
                                        WHERE r.role_code = :code)
                        """)
                .param("code", code)
                .query(Boolean.class)
                .single();
    }

    public void deleteRole(String code) {
        jdbc.sql("DELETE FROM app_role WHERE role_code = :code").param("code", code).update();
    }

    // --- Tenant ---

    public List<TenantView> listTenants() {
        return jdbc.sql("SELECT code, description FROM tenant ORDER BY code")
                .query((rs, n) -> new TenantView(rs.getString(1), rs.getString(2)))
                .list();
    }

    public Optional<TenantView> findTenant(String code) {
        return jdbc.sql("SELECT code, description FROM tenant WHERE code = :code")
                .param("code", code)
                .query((rs, n) -> new TenantView(rs.getString(1), rs.getString(2)))
                .optional();
    }

    /** Lock sulla riga del tenant: serializza le modifiche concorrenti alle assegnazioni dello stesso tenant. */
    public boolean lockTenant(String code) {
        return jdbc.sql("SELECT code FROM tenant WHERE code = :code FOR UPDATE")
                .param("code", code)
                .query(String.class)
                .optional()
                .isPresent();
    }

    public void insertTenant(String code, String description) {
        jdbc.sql("INSERT INTO tenant (code, description) VALUES (:code, :description)")
                .param("code", code)
                .param("description", description)
                .update();
    }

    // --- Utenti e assegnazioni ---

    public Optional<UserRow> findUser(String username) {
        return jdbc.sql("SELECT id, username, email, is_active FROM app_user WHERE username = :username")
                .param("username", username)
                .query((rs, n) -> new UserRow(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3),
                        rs.getBoolean(4)))
                .optional();
    }

    public void insertUser(String username, String email) {
        jdbc.sql("INSERT INTO app_user (username, email) VALUES (:username, :email)")
                .param("username", username)
                .param("email", email)
                .update();
    }

    public void updateUser(String username, boolean active, String email) {
        jdbc.sql("UPDATE app_user SET is_active = :active, email = :email WHERE username = :username")
                .param("username", username)
                .param("active", active)
                .param("email", email)
                .update();
    }

    /** Assegnazioni dell'utente: tenant -> ruoli, ordinate. */
    public SortedMap<String, SortedSet<String>> userAssignments(UUID userId) {
        SortedMap<String, SortedSet<String>> result = new TreeMap<>();
        jdbc.sql("""
                        SELECT ur.tenant_id, r.role_code FROM user_role ur JOIN app_role r ON r.id = ur.role_id
                         WHERE ur.user_id = :userId
                        """)
                .param("userId", userId)
                .query((rs, n) -> Map.entry(rs.getString(1), rs.getString(2)))
                .list()
                .forEach(e -> result.computeIfAbsent(e.getKey(), k -> new TreeSet<>()).add(e.getValue()));
        return result;
    }

    /** Utenti con almeno un ruolo sul tenant, paginati per username, con i ruoli di quel tenant. */
    public List<TenantUserView> tenantUsers(String tenant, int limit, int offset) {
        Map<String, TenantUserView> users = new LinkedHashMap<>();
        jdbc.sql("""
                        SELECT u.username, u.email, u.is_active, r.role_code
                          FROM app_user u
                          JOIN user_role ur ON ur.user_id = u.id AND ur.tenant_id = :tenant
                          JOIN app_role r   ON r.id = ur.role_id
                         WHERE u.id IN (SELECT u2.id FROM app_user u2
                                         WHERE EXISTS (SELECT 1 FROM user_role ur2
                                                        WHERE ur2.user_id = u2.id AND ur2.tenant_id = :tenant)
                                         ORDER BY u2.username LIMIT :limit OFFSET :offset)
                         ORDER BY u.username, r.role_code
                        """)
                .param("tenant", tenant)
                .param("limit", limit)
                .param("offset", offset)
                .query((rs, n) -> new TenantUserRow(rs.getString(1), rs.getString(2), rs.getBoolean(3),
                        rs.getString(4)))
                .list()
                .forEach(row -> users.computeIfAbsent(row.username(),
                                u -> new TenantUserView(u, row.email(), row.active(), new TreeSet<>()))
                        .roles().add(row.role()));
        return List.copyOf(users.values());
    }

    public void replaceUserRoles(UUID userId, String tenant, Collection<String> roleCodes) {
        jdbc.sql("DELETE FROM user_role WHERE user_id = :userId AND tenant_id = :tenant")
                .param("userId", userId)
                .param("tenant", tenant)
                .update();
        if (!roleCodes.isEmpty()) {
            jdbc.sql("""
                            INSERT INTO user_role (user_id, role_id, tenant_id)
                            SELECT :userId, id, :tenant FROM app_role WHERE role_code IN (:roles)
                            """)
                    .param("userId", userId)
                    .param("tenant", tenant)
                    .param("roles", roleCodes)
                    .update();
        }
    }

    public boolean hasAnyRole(UUID userId) {
        return jdbc.sql("SELECT EXISTS (SELECT 1 FROM user_role WHERE user_id = :userId)")
                .param("userId", userId)
                .query(Boolean.class)
                .single();
    }

    /** Elimina l'utente; i suoi token personali vanno con lui (ON DELETE CASCADE). */
    public void deleteUser(UUID userId) {
        jdbc.sql("DELETE FROM app_user WHERE id = :userId").param("userId", userId).update();
    }

    // --- Audit ---

    public record AuditRow(long id, String actor, String target, String beforeState, String afterState) {
    }

    /**
     * Voci di audit del tenant (e, con {@code withoutTenant}, quelle senza tenant) che nominano l'utente come autore,
     * come oggetto o in uno stato JSON. {@code quoted} e' il nome come stringa JSON, cercato nel testo degli stati.
     */
    public List<AuditRow> auditMentioning(String tenant, boolean withoutTenant, String username, String quoted) {
        String like = "%" + quoted.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%";
        return jdbc.sql("""
                        SELECT id, actor, target, before_state::text, after_state::text
                          FROM rbac_audit
                         WHERE (tenant_id = :tenant OR (:withoutTenant AND tenant_id IS NULL))
                           AND (actor = :username OR target = :username
                                OR before_state::text LIKE :like ESCAPE '\\'
                                OR after_state::text LIKE :like ESCAPE '\\')
                         ORDER BY id
                         FOR UPDATE
                        """)
                .param("tenant", tenant)
                .param("withoutTenant", withoutTenant)
                .param("username", username)
                .param("like", like)
                .query((rs, n) -> new AuditRow(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5)))
                .list();
    }

    public void updateAudit(AuditRow row) {
        jdbc.sql("""
                        UPDATE rbac_audit SET actor = :actor, target = :target,
                               before_state = CAST(:before AS JSONB), after_state = CAST(:after AS JSONB)
                         WHERE id = :id
                        """)
                .param("id", row.id())
                .param("actor", row.actor())
                .param("target", row.target())
                .param("before", row.beforeState())
                .param("after", row.afterState())
                .update();
    }

    public void insertAudit(AdminScope actor, String action, String targetType, String target, String tenantId,
                            String beforeJson, String afterJson) {
        jdbc.sql("""
                        INSERT INTO rbac_audit (actor, actor_tenant, action, target_type, target, tenant_id,
                                                before_state, after_state)
                        VALUES (:actor, :actorTenant, :action, :targetType, :target, :tenantId,
                                CAST(:before AS JSONB), CAST(:after AS JSONB))
                        """)
                .param("actor", actor.username())
                .param("actorTenant", actor.tenantId())
                .param("action", action)
                .param("targetType", targetType)
                .param("target", target)
                .param("tenantId", tenantId)
                .param("before", beforeJson)
                .param("after", afterJson)
                .update();
    }

    /** Voci di audit, piu' recenti prima; tenant null = tutti i tenant. */
    public List<AuditEntry> listAudit(String tenant, int limit, int offset) {
        return jdbc.sql("""
                        SELECT id, occurred_at, actor, actor_tenant, action, target_type, target, tenant_id,
                               before_state::text, after_state::text
                          FROM rbac_audit
                         WHERE (CAST(:tenant AS VARCHAR) IS NULL OR tenant_id = :tenant)
                         ORDER BY occurred_at DESC, id DESC
                         LIMIT :limit OFFSET :offset
                        """)
                .param("tenant", tenant)
                .param("limit", limit)
                .param("offset", offset)
                .query((rs, n) -> new AuditEntry(rs.getLong(1), rs.getObject(2, OffsetDateTime.class),
                        rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7),
                        rs.getString(8), rs.getString(9), rs.getString(10)))
                .list();
    }

    private RoleRow roleRow(java.sql.ResultSet rs, int n) throws java.sql.SQLException {
        return new RoleRow(rs.getString(1), rs.getString(2), rs.getBoolean(3), rs.getInt(4), rs.getString(5));
    }

    private static List<RoleView> toRoles(List<RoleRow> rows) {
        Map<String, RoleView> roles = new LinkedHashMap<>();
        for (RoleRow row : rows) {
            RoleView role = roles.computeIfAbsent(row.code(),
                    c -> new RoleView(c, row.description(), row.system(), row.version(), new TreeSet<>()));
            if (row.permission() != null) {
                role.permissions().add(row.permission());
            }
        }
        return List.copyOf(roles.values());
    }
}
