package com.logicwarez.authz.rbac;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.logicwarez.authz.rbac.admin.AdminApi.RoleAssignmentRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleCreateRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleUpdateRequest;
import com.logicwarez.authz.rbac.admin.AdminProblem;
import com.logicwarez.authz.rbac.admin.AdminScope;
import com.logicwarez.authz.rbac.admin.RbacAdminService;
import com.logicwarez.authz.rbac.service.AuthorizationContext;
import com.logicwarez.authz.rbac.service.AuthorizationService;
import com.logicwarez.authz.session.UserNotAuthorizedException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * authz-rbac su un PostgreSQL vero: migrazioni con la history propria, risoluzione dei permessi al login, regole
 * dell'amministrazione e audit. Ogni test crea i propri tenant e utenti con un suffisso casuale (database condiviso).
 * Senza Docker il test viene saltato.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = RbacPostgresTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
class RbacPostgresTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17");

    @Autowired
    JdbcClient jdbc;

    @Autowired
    AuthorizationService authorization;

    @Autowired
    RbacAdminService admin;

    // --- Migrazioni ---

    @Test
    void migrazioniNellaHistoryPropria() {
        List<String> versions = jdbc.sql("SELECT version FROM authz_schema_history WHERE success ORDER BY installed_rank")
                .query(String.class).list();
        assertThat(versions).containsExactly("1", "2", "3");
        assertThat(jdbc.sql("SELECT permission_code FROM app_permission ORDER BY 1").query(String.class).list())
                .containsExactly("authz.rbac.manage", "authz.rbac.manageglobal",
                        "authz.session.revoke", "authz.session.revokeglobal");
    }

    @Test
    void formatoDeiPermessiImpostoDalDatabase() {
        assertThatThrownBy(() -> jdbc.sql("INSERT INTO app_permission (permission_code) VALUES ('patient:read')").update())
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("ck_permission_code_format");
    }

    // --- Risoluzione al login ---

    @Test
    void tenantDelLoginPrimoPoiUltimoUsato() {
        String a = tenant("A"), b = tenant("B");
        String user = user();
        String role = role("demo.item.read");
        assign(user, role, a);
        assign(user, role, b);

        AuthorizationContext first = authorization.resolve(user, null);
        assertThat(first.tenantId()).isEqualTo(a);
        assertThat(first.availableTenants()).containsOnlyKeys(a, b);
        assertThat(first.permissions()).containsExactly("demo.item.read");

        assertThat(authorization.resolve(user, b).tenantId()).isEqualTo(b);
        assertThat(authorization.resolve(user, null).tenantId()).as("ultimo tenant usato").isEqualTo(b);
    }

    @Test
    void permessiSoloDelTenantScelto() {
        String a = tenant("A"), b = tenant("B");
        String user = user();
        assign(user, role("demo.item.read"), a);
        assign(user, role("demo.item.edit"), b);

        assertThat(authorization.resolve(user, a).permissions()).containsExactly("demo.item.read");
        assertThat(authorization.resolve(user, b).permissions()).containsExactly("demo.item.edit");
    }

    @Test
    void tenantSenzaRuoliUtenteSenzaRuoliOInattivo() {
        String a = tenant("A");
        String user = user();
        assertThatThrownBy(() -> authorization.resolve(user, null)).isInstanceOf(UserNotAuthorizedException.class);

        assign(user, role("demo.item.read"), a);
        assertThatThrownBy(() -> authorization.resolve(user, tenant("ALTRO")))
                .isInstanceOf(UserNotAuthorizedException.class);

        jdbc.sql("UPDATE app_user SET is_active = FALSE WHERE username = ?").param(user).update();
        assertThatThrownBy(() -> authorization.resolve(user, a)).isInstanceOf(UserNotAuthorizedException.class);
    }

    // --- Amministrazione ---

    @Test
    void delegatoAssegnaRuoliSulProprioTenantConAudit() {
        String a = tenant("A");
        String user = user();
        String role = role("demo.item.read");
        AdminScope delegate = new AdminScope("delegato-" + suffix(), a, Set.of(AdminScope.MANAGE));

        assertThat(admin.replaceUserRoles(delegate, a, user, new RoleAssignmentRequest(List.of(role))).assignments())
                .containsEntry(a, new java.util.TreeSet<>(List.of(role)));
        assertThat(jdbc.sql("SELECT count(*) FROM rbac_audit WHERE action = 'USER_ROLES_REPLACED' AND target = ? AND actor = ?")
                .param(user).param(delegate.username()).query(Long.class).single()).isEqualTo(1);
    }

    @Test
    void delegatoNonPromuoveAdAmministratoreGlobale() {
        String a = tenant("A");
        String user = user();
        AdminScope delegate = new AdminScope("delegato-" + suffix(), a, Set.of(AdminScope.MANAGE));

        assertProblem(() -> admin.replaceUserRoles(delegate, a, user, new RoleAssignmentRequest(List.of("GLOBAL_ADMIN"))),
                "global-role");
        assertProblem(() -> admin.replaceUserRoles(delegate, tenant("B"), user, new RoleAssignmentRequest(List.of())),
                "tenant-out-of-scope");
        assertProblem(() -> admin.replaceUserRoles(delegate, a, delegate.username(), new RoleAssignmentRequest(List.of())),
                "self-modification");
        assertThat(jdbc.sql("SELECT count(*) FROM user_role ur JOIN app_user u ON u.id = ur.user_id WHERE u.username = ?")
                .param(user).query(Long.class).single()).as("nessuna assegnazione scritta").isZero();
    }

    @Test
    void ruoloConBloccoOttimistico() {
        AdminScope global = new AdminScope("globale-" + suffix(), "DEFAULT", Set.of(AdminScope.MANAGE_GLOBAL));
        String code = "R_" + suffix().toUpperCase();
        int version = admin.createRole(global, new RoleCreateRequest(code, "Prova", List.of("authz.session.revoke")))
                .version();

        assertThat(admin.updateRole(global, code, new RoleUpdateRequest("Prova 2", List.of(), version)).version())
                .isEqualTo(version + 1);
        assertProblem(() -> admin.updateRole(global, code, new RoleUpdateRequest("Prova 3", List.of(), version)),
                "version-mismatch");
        assertProblem(() -> admin.updateRole(global, code,
                new RoleUpdateRequest("Prova 3", List.of("authz.rbac.manageglobal"), version + 1)), "global-permission");
    }

    // --- Dati di prova ---

    private String tenant(String name) {
        String code = name + "_" + suffix().toUpperCase();
        jdbc.sql("INSERT INTO tenant (code, description) VALUES (?, ?)").param(code).param("Sede " + name).update();
        return code;
    }

    private String user() {
        String username = "utente-" + suffix();
        jdbc.sql("INSERT INTO app_user (username, email) VALUES (?, ?)").param(username).param(username + "@example.org")
                .update();
        return username;
    }

    private String role(String permission) {
        jdbc.sql("INSERT INTO app_permission (permission_code) VALUES (?) ON CONFLICT DO NOTHING").param(permission)
                .update();
        String code = "ROLE_" + suffix().toUpperCase();
        jdbc.sql("INSERT INTO app_role (role_code) VALUES (?)").param(code).update();
        jdbc.sql("""
                INSERT INTO role_permission (role_id, permission_id)
                SELECT r.id, p.id FROM app_role r, app_permission p WHERE r.role_code = ? AND p.permission_code = ?""")
                .param(code).param(permission).update();
        return code;
    }

    private void assign(String username, String role, String tenant) {
        jdbc.sql("""
                INSERT INTO user_role (user_id, role_id, tenant_id)
                SELECT u.id, r.id, ? FROM app_user u, app_role r WHERE u.username = ? AND r.role_code = ?""")
                .param(tenant).param(username).param(role).update();
    }

    private static String suffix() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    private static void assertProblem(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, String code) {
        assertThatThrownBy(call).isInstanceOfSatisfying(AdminProblem.class, p -> assertThat(p.code()).isEqualTo(code));
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class TestApp {
    }
}
