package com.logicwarez.authz.rbac.admin;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import com.logicwarez.authz.rbac.RbacAutoConfiguration;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Genera con springdoc la definizione OpenAPI di /api/v1/admin/** e la confronta con
 * docs/authz-admin-openapi-spec.json: se il controller cambia e la definizione no, il build fallisce.
 * Per aggiornarla: {@code mvn -pl authz-rbac -am test -Dtest=AdminOpenApiTest -Dsurefire.failIfNoSpecifiedTests=false
 * -Dopenapi.update=true}. La copia generata resta comunque in target/authz-admin-openapi-spec.json.
 */
@SpringBootTest(classes = AdminOpenApiTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"springdoc.writer-with-order-by-keys=true", "springdoc.paths-to-match=/api/v1/admin/**"})
class AdminOpenApiTest {

    static final Path SPEC = Path.of("..", "docs", "authz-admin-openapi-spec.json");

    private static final JsonMapper JSON = JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build();

    @LocalServerPort
    int port;

    @Test
    void definizioneAggiornata() throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v3/api-docs")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        // L'indentazione usa il separatore di riga del sistema: LF ovunque, per avere lo stesso file su Windows e in CI
        String generated = JSON.writeValueAsString(JSON.readTree(response.body())).replace("\r\n", "\n") + "\n";

        Files.writeString(Path.of("target", SPEC.getFileName().toString()), generated, StandardCharsets.UTF_8);
        if (Boolean.getBoolean("openapi.update")) {
            Files.writeString(SPEC, generated, StandardCharsets.UTF_8);
            return;
        }
        assertThat(Files.readString(SPEC, StandardCharsets.UTF_8).replace("\r\n", "\n"))
                .as("%s non corrisponde al controller: rigenerarla con -Dopenapi.update=true (vedi javadoc)", SPEC)
                .isEqualTo(generated);
    }

    /** Solo il controller e la gestione degli errori, con il servizio finto: niente database, niente scan. */
    @SpringBootConfiguration
    @EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class, RbacAutoConfiguration.class})
    @EnableSpringHttpSession
    @Import({RbacAdminController.class, RbacAdminExceptionHandler.class})
    static class TestApp {

        @Bean
        RbacAdminService rbacAdminService() {
            return Mockito.mock(RbacAdminService.class);
        }

        @Bean
        MapSessionRepository sessionRepository() {
            return new MapSessionRepository(new java.util.concurrent.ConcurrentHashMap<>());
        }

        @Bean
        SecurityFilterChain security(HttpSecurity http) {
            http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
            return http.build();
        }

        @Bean
        OpenAPI adminOpenApi() {
            return new OpenAPI()
                    .info(new Info().title("ms-authz - API di amministrazione RBAC").version("v1").description(DESCRIPTION))
                    .servers(List.of(new Server().url("http://localhost:8080").description("Applicazione con authz-bff")))
                    .components(new Components().addSecuritySchemes("sessionCookie",
                            new SecurityScheme().type(SecurityScheme.Type.APIKEY).in(SecurityScheme.In.COOKIE)
                                    .name("SESSION_ID")))
                    .addSecurityItem(new SecurityRequirement().addList("sessionCookie"));
        }

        private static final String DESCRIPTION = """
                API per l'interfaccia di amministrazione della SPA, esposte dall'applicazione che incorpora authz-bff e \
                authz-rbac (stessa origine della SPA).

                **Autenticazione**: cookie di sessione impostato dal BFF al login (`SESSION_ID` nell'applicazione di \
                esempio; nessun token nel JavaScript). Le richieste `POST`, `PUT`, `PATCH`, `DELETE` devono avere \
                l'header `X-XSRF-TOKEN` con il valore del cookie `XSRF-TOKEN`; un header `Origin` presente deve essere \
                un'origine ammessa.

                **Ambiti**
                - `authz.rbac.manage` (ruolo `TENANT_ADMIN`): amministratore delegato, solo il tenant della propria \
                sessione.
                - `authz.rbac.manageglobal` (ruolo `GLOBAL_ADMIN`): tutti i tenant; in esclusiva definisce ruoli, crea \
                tenant, attiva e disattiva utenti.

                **Regole**
                - Il catalogo dei permessi e i ruoli di sistema (`system: true`) si modificano solo con le migrazioni.
                - I permessi la cui azione finisce in `global` esistono solo in `GLOBAL_ADMIN`; un amministratore \
                delegato non assegna né toglie ruoli che li contengono.
                - Nessuno può modificare le proprie assegnazioni o disattivare se stesso.
                - Le modifiche hanno effetto al login successivo degli utenti coinvolti; per un effetto immediato si \
                revocano le sessioni con `DELETE /bff/admin/users/{username}/sessions` (endpoint di authz-bff).
                - Ogni modifica è registrata nell'audit.

                **Errori**: `application/problem+json` (RFC 9457), `type` = `urn:problem:auth-service:<codice>`: \
                `tenant-out-of-scope`, `global-admin-required`, `global-role`, `self-modification`, `system-role`, \
                `access-denied` (403); `unknown-role`, `unknown-permission`, `global-permission` (400); `not-found` \
                (404); `version-mismatch`, `role-exists`, `role-assigned`, `tenant-exists`, `user-exists` (409).
                """;
    }
}
