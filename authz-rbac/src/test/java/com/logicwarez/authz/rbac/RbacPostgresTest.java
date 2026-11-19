package com.logicwarez.authz.rbac;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.logicwarez.authz.rbac.admin.AdminApi.ForgetResult;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleAssignmentRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleCreateRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleUpdateRequest;
import com.logicwarez.authz.rbac.admin.AdminProblem;
import com.logicwarez.authz.rbac.admin.AdminScope;
import com.logicwarez.authz.rbac.admin.RbacAdminService;
import com.logicwarez.authz.rbac.directory.TenantDirectory;
import com.logicwarez.authz.rbac.service.AuthorizationContext;
import com.logicwarez.authz.rbac.service.AuthorizationService;
import com.logicwarez.authz.rbac.token.PersonalAccessTokens;
import com.logicwarez.authz.session.PersonalAccessTokenVerifier;
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
@SpringBootTest(classes = RbacPostgresTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {"authz.rbac.tokens.enabled=true", "authz.rbac.tokens.max-per-user=2"})
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

    @Autowired
    TenantDirectory directory;

    @Autowired
    PersonalAccessTokens tokens;

    // --- Migrazioni ---

    @Test
    void migrazioniNellaHistoryPropria() {
        List<String> versions = jdbc.sql("SELECT version FROM authz_schema_history WHERE success ORDER BY installed_rank")
                .query(String.class).list();
        assertThat(versions).containsExactly("1", "2", "3", "4");
        assertThat(jdbc.sql("SELECT permission_code FROM app_permission WHERE permission_code LIKE 'authz.%' ORDER BY 1").query(String.class).list())
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

    @Test
    void risoluzionePerUnTokenNonCambiaLUltimoTenant() {
        String a = tenant("A"), b = tenant("B");
        String user = user();
        String role = role("demo.item.read");
        assign(user, role, a);
        assign(user, role, b);
        authorization.resolve(user, a);

        assertThat(authorization.resolve(user, b, false).tenantId()).isEqualTo(b);
        assertThat(authorization.resolve(user, null).tenantId()).as("ultimo tenant invariato").isEqualTo(a);
    }

    // --- Directory del tenant ---

    @Test
    void directorySoloUtentiAttiviConUnRuoloSulTenant() {
        String a = tenant("A"), b = tenant("B");
        String role = role("demo.item.read");
        String marker = suffix();
        String mario = user("mario_" + marker), maria = user("maria_" + marker), altro = user("mariano_" + marker);
        String inattivo = user("marietto_" + marker);
        assign(mario, role, a);
        assign(maria, role, a);
        assign(altro, role, b);
        assign(inattivo, role, a);
        jdbc.sql("UPDATE app_user SET is_active = FALSE WHERE username = ?").param(inattivo).update();

        assertThat(directory.search(a, "MAR", 50)).extracting(TenantDirectory.DirectoryUser::username)
                .containsExactly(maria, mario);
        assertThat(directory.search(a, marker, 1)).hasSize(1);
        assertThat(directory.search(a, "%", 50)).as("caratteri jolly letterali").isEmpty();
        assertThat(directory.find(a, mario)).hasValueSatisfying(u -> assertThat(u.email()).isEqualTo(mario + "@example.org"));
        assertThat(directory.find(a, altro)).isEmpty();
        assertThat(directory.find(a, inattivo)).isEmpty();
    }

    // --- Token personali ---

    @Test
    void tokenPersonaliCreatiVerificatiERevocati() {
        String user = user();
        PersonalAccessTokens.CreatedToken created = tokens.create(user, "CI", 30);
        assertThat(created.token()).startsWith(PersonalAccessTokenVerifier.PREFIX);
        assertThat(jdbc.sql("SELECT count(*) FROM personal_access_token WHERE token_hash = ?").param(created.token())
                .query(Long.class).single()).as("solo l'hash nel database").isZero();

        assertThat(tokens.verify(created.token())).hasValueSatisfying(o -> assertThat(o.username()).isEqualTo(user));
        assertThat(tokens.verify(created.token() + "x")).isEmpty();
        assertThat(tokens.list(user)).singleElement().satisfies(t -> {
            assertThat(t.name()).isEqualTo("CI");
            assertThat(created.token()).startsWith(t.hint());
            assertThat(t.lastUsedAt()).isNotNull();
        });

        tokens.revoke(user, created.id());
        assertThat(tokens.verify(created.token())).isEmpty();
        assertThat(tokens.list(user)).isEmpty();
        assertThatThrownBy(() -> tokens.revoke(user, created.id()))
                .isInstanceOfSatisfying(PersonalAccessTokens.TokenException.class, e -> assertThat(e.status()).isEqualTo(404));
        assertThat(jdbc.sql("SELECT count(*) FROM rbac_audit WHERE actor = ? AND action IN ('TOKEN_CREATED', 'TOKEN_REVOKED')")
                .param(user).query(Long.class).single()).isEqualTo(2);
    }

    @Test
    void tokenPersonaliLimitiEUtentiInattivi() {
        String user = user();
        assertTokenProblem(() -> tokens.create(user, "lungo", 400), 400);
        String first = tokens.create(user, "uno", 10).token();
        tokens.create(user, "due", 10);
        assertTokenProblem(() -> tokens.create(user, "tre", 10), 409);
        assertThatThrownBy(() -> tokens.revoke(user(), tokens.list(user).getFirst().id()))
                .as("token di un altro utente").isInstanceOf(PersonalAccessTokens.TokenException.class);

        jdbc.sql("UPDATE app_user SET is_active = FALSE WHERE username = ?").param(user).update();
        assertThat(tokens.verify(first)).isEmpty();
        assertTokenProblem(() -> tokens.create(user, "quattro", 10), 403);
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

    // --- Pseudonimizzazione ---

    @Test
    void forgetUserPseudonimizzaLAuditDelTenantEdEliminaLUtente() {
        String a = tenant("A"), b = tenant("B");
        String user = user();
        String similar = user(user + "z");
        String role = role("demo.item.read");
        AdminScope delegate = new AdminScope("delegato-" + suffix(), a, Set.of(AdminScope.MANAGE));
        admin.replaceUserRoles(delegate, a, user, new RoleAssignmentRequest(List.of(role)));
        UUID token = tokens.create(user, "CI", 30).id();
        audit(user, a, "ITEM_CHANGED", "ITEM", "42",
                "{\"owner\": \"" + user + "\", \"watchers\": [\"" + similar + "\", {\"by\": \"" + user + "\"}]}");
        audit("altro", b, "ITEM_CHANGED", "USER", user, "{\"owner\": \"" + user + "\"}");

        assertProblem(() -> admin.forgetUser(delegate, a, user, "anonimo-" + suffix()), "user-has-roles");
        admin.replaceUserRoles(delegate, a, user, new RoleAssignmentRequest(List.of()));
        String pseudonym = "anonimo-" + suffix();
        ForgetResult result = admin.forgetUser(delegate, a, user, pseudonym);

        assertThat(result).isEqualTo(new ForgetResult(pseudonym, a, 4, true));
        assertThat(admin.findUser(delegate, user)).isEmpty();
        assertThat(jdbc.sql("SELECT count(*) FROM personal_access_token WHERE id = ?").param(token).query(Long.class).single())
                .as("token eliminati con l'utente").isZero();
        assertThat(jdbc.sql("""
                        SELECT count(*) FROM rbac_audit WHERE (tenant_id = ? OR tenant_id IS NULL)
                           AND (actor = ? OR target = ? OR before_state::text LIKE ? OR after_state::text LIKE ?)""")
                .param(a).param(user).param(user).param("%\"" + user + "\"%").param("%\"" + user + "\"%")
                .query(Long.class).single()).as("nome sparito dal tenant e dalle voci senza tenant").isZero();
        assertThat(jdbc.sql("SELECT after_state::text FROM rbac_audit WHERE tenant_id = ? AND action = 'ITEM_CHANGED'")
                .param(a).query(String.class).single())
                .contains("\"owner\": \"" + pseudonym + "\"", "\"by\": \"" + pseudonym + "\"", "\"" + similar + "\"");
        assertThat(jdbc.sql("SELECT count(*) FROM rbac_audit WHERE tenant_id = ? AND target = ? AND after_state::text LIKE ?")
                .param(b).param(user).param("%" + user + "%").query(Long.class).single())
                .as("altro tenant invariato").isEqualTo(1);
        assertThat(jdbc.sql("SELECT after_state::text FROM rbac_audit WHERE action = 'USER_FORGOTTEN' AND target = ?")
                .param(pseudonym).query(String.class).single()).doesNotContain(user);

        assertThat(admin.forgetUser(delegate, a, user, pseudonym + "x")).as("si puo' ripetere")
                .isEqualTo(new ForgetResult(pseudonym + "x", a, 0, false));
    }

    @Test
    void forgetUserRegoleDiReplaceUserRoles() {
        String a = tenant("A"), b = tenant("B");
        String user = user();
        String role = role("demo.item.read");
        assign(user, role, b);
        AdminScope delegate = new AdminScope("delegato-" + suffix(), a, Set.of(AdminScope.MANAGE));

        assertProblem(() -> admin.forgetUser(delegate, b, user, "anonimo-" + suffix()), "tenant-out-of-scope");
        assertProblem(() -> admin.forgetUser(delegate, a, delegate.username(), "anonimo-" + suffix()),
                "self-modification");
        assertProblem(() -> admin.forgetUser(delegate, a, user, user), "invalid-pseudonym");
        assertProblem(() -> admin.forgetUser(delegate, a, user, "non valido"), "invalid-pseudonym");
        assertProblem(() -> admin.forgetUser(delegate, a, user, user()), "pseudonym-exists");
        AdminScope global = new AdminScope("globale-" + suffix(), "DEFAULT", Set.of(AdminScope.MANAGE_GLOBAL));
        assertProblem(() -> admin.forgetUser(global, "NESSUNO_" + suffix(), user, "anonimo-" + suffix()), "not-found");

        assertThat(admin.forgetUser(delegate, a, user, "anonimo-" + suffix()).userDeleted())
                .as("ha ancora ruoli su un altro tenant").isFalse();
        assertThat(admin.findUser(delegate, user)).hasValueSatisfying(u -> assertThat(u.username()).isEqualTo(user));

        String inactive = user();
        jdbc.sql("UPDATE app_user SET is_active = FALSE WHERE username = ?").param(inactive).update();
        assertThat(admin.forgetUser(delegate, a, inactive, "anonimo-" + suffix()).userDeleted())
                .as("il delegato non elimina un utente disattivato").isFalse();
        assertThat(admin.forgetUser(global, a, inactive, "anonimo-" + suffix()).userDeleted()).isTrue();
        assertThat(admin.findUser(global, "sconosciuto-" + suffix())).isEmpty();
    }

    // --- Dati di prova ---

    private void audit(String actor, String tenant, String action, String targetType, String target, String after) {
        jdbc.sql("""
                INSERT INTO rbac_audit (actor, action, target_type, target, tenant_id, after_state)
                VALUES (?, ?, ?, ?, ?, CAST(? AS JSONB))""")
                .param(actor).param(action).param(targetType).param(target).param(tenant).param(after).update();
    }

    private String tenant(String name) {
        String code = name + "_" + suffix().toUpperCase();
        jdbc.sql("INSERT INTO tenant (code, description) VALUES (?, ?)").param(code).param("Sede " + name).update();
        return code;
    }

    private String user() {
        return user("utente-" + suffix());
    }

    private String user(String username) {
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

    private static void assertTokenProblem(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, int status) {
        assertThatThrownBy(call).isInstanceOfSatisfying(PersonalAccessTokens.TokenException.class,
                e -> assertThat(e.status()).isEqualTo(status));
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class TestApp {
    }
}
