package com.logicwarez.authz.rbac;

import java.util.List;

import com.logicwarez.authz.rbac.directory.TenantDirectory;
import com.logicwarez.authz.rbac.service.AuthorizationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tabelle in uno schema dedicato ({@code authz.rbac.schema}): migrazioni, history e query della libreria restano
 * nello schema, lo schema public dell'applicazione non viene toccato. Senza Docker il test viene saltato.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = RbacSchemaTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = "authz.rbac.schema=authz")
class RbacSchemaTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17");

    @Autowired
    JdbcClient jdbc;

    @Autowired
    AuthorizationService authorization;

    @Autowired
    TenantDirectory directory;

    @Test
    void tabelleEHistoryNelloSchemaDedicato() {
        List<String> schemas = jdbc.sql("""
                        SELECT DISTINCT table_schema FROM information_schema.tables
                         WHERE table_name IN ('app_user', 'authz_schema_history', 'personal_access_token')""")
                .query(String.class).list();
        assertThat(schemas).containsExactly("authz");
        assertThat(jdbc.sql("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")
                .query(Long.class).single()).isZero();
    }

    @Test
    void queryQualificateConLoSchema() {
        jdbc.sql("INSERT INTO authz.tenant (code, description) VALUES ('SEDE', 'Sede')").update();
        jdbc.sql("INSERT INTO authz.app_user (username, email) VALUES ('lucia', 'lucia@example.org')").update();
        jdbc.sql("INSERT INTO authz.app_role (role_code) VALUES ('LETTORE')").update();
        jdbc.sql("""
                INSERT INTO authz.role_permission (role_id, permission_id)
                SELECT r.id, p.id FROM authz.app_role r, authz.app_permission p
                 WHERE r.role_code = 'LETTORE' AND p.permission_code = 'authz.session.revoke'""").update();
        jdbc.sql("""
                INSERT INTO authz.user_role (user_id, role_id, tenant_id)
                SELECT u.id, r.id, 'SEDE' FROM authz.app_user u, authz.app_role r
                 WHERE u.username = 'lucia' AND r.role_code = 'LETTORE'""").update();

        assertThat(authorization.resolve("lucia", null).permissions()).containsExactly("authz.session.revoke");
        assertThat(directory.search("SEDE", "luc", 10)).extracting(TenantDirectory.DirectoryUser::username)
                .containsExactly("lucia");
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class TestApp {
    }
}
