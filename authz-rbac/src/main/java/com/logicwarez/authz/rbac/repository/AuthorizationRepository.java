package com.logicwarez.authz.rbac.repository;

import com.logicwarez.authz.rbac.RbacJdbc;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Accesso al modello RBAC con JdbcClient: una sola query in join per recuperare
 * tutte le coppie (tenant, ruolo, permesso) dell'utente, sfruttando gli indici di PK.
 */
@Repository
public class AuthorizationRepository {

    /**
     * @param lastTenantId tenant dell'ultima sessione, null se mai registrato
     * @param lastRole     ruolo operativo dell'ultima sessione, null se mai registrato
     */
    public record ActiveUser(UUID id, String username, String email, String lastTenantId, String lastRole) {

        public ActiveUser(UUID id, String username, String email, String lastTenantId) {
            this(id, username, email, lastTenantId, null);
        }
    }

    /**
     * @param tenantLabel descrizione del tenant, null se assente
     * @param roleLabel   descrizione del ruolo, null se assente
     * @param baseRole    ruolo di base (vale sempre) o operativo (uno alla volta)
     */
    public record GrantRow(String tenantId, String tenantLabel, String roleCode, String permissionCode,
                           String roleLabel, boolean baseRole) {

        /** Un ruolo di base, senza descrizione. */
        public GrantRow(String tenantId, String tenantLabel, String roleCode, String permissionCode) {
            this(tenantId, tenantLabel, roleCode, permissionCode, null, true);
        }
    }

    private static final String FIND_ACTIVE_USER = """
            SELECT id, username, email, last_tenant_id, last_role_code
              FROM app_user
             WHERE username = :username
               AND is_active = TRUE
            """;

    private static final String FIND_GRANTS = """
            SELECT ur.tenant_id, t.description AS tenant_label, r.role_code, p.permission_code,
                   r.description AS role_label, r.is_base
              FROM user_role ur
              JOIN app_role r             ON r.id = ur.role_id
              LEFT JOIN tenant t           ON t.code = ur.tenant_id
              LEFT JOIN role_permission rp ON rp.role_id = r.id
              LEFT JOIN app_permission p   ON p.id = rp.permission_id
             WHERE ur.user_id = :userId
            """;

    private static final String UPDATE_LAST_TENANT = """
            UPDATE app_user SET last_tenant_id = :tenant
             WHERE id = :userId
               AND last_tenant_id IS DISTINCT FROM :tenant
            """;

    private static final String UPDATE_LAST_ROLE = """
            UPDATE app_user SET last_role_code = :role
             WHERE id = :userId
               AND last_role_code IS DISTINCT FROM :role
            """;

    private final RbacJdbc jdbc;

    public AuthorizationRepository(RbacJdbc jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<ActiveUser> findActiveUser(String username) {
        return jdbc.sql(FIND_ACTIVE_USER)
                .param("username", username)
                .query((rs, n) -> new ActiveUser(
                        rs.getObject("id", UUID.class),
                        rs.getString("username"),
                        rs.getString("email"),
                        rs.getString("last_tenant_id"),
                        rs.getString("last_role_code")))
                .optional();
    }

    public List<GrantRow> findGrants(UUID userId) {
        return jdbc.sql(FIND_GRANTS)
                .param("userId", userId)
                .query((rs, n) -> new GrantRow(
                        rs.getString("tenant_id"),
                        rs.getString("tenant_label"),
                        rs.getString("role_code"),
                        rs.getString("permission_code"),
                        rs.getString("role_label"),
                        rs.getBoolean("is_base")))
                .list();
    }

    /** Ricorda il ruolo operativo della sessione: al login successivo l'utente rientra su questo. */
    public void updateLastRole(UUID userId, String role) {
        jdbc.sql(UPDATE_LAST_ROLE)
                .param("userId", userId)
                .param("role", role)
                .update();
    }

    /** Ricorda il tenant della sessione: al login successivo l'utente rientra su questo. */
    public void updateLastTenant(UUID userId, String tenant) {
        jdbc.sql(UPDATE_LAST_TENANT)
                .param("userId", userId)
                .param("tenant", tenant)
                .update();
    }
}
