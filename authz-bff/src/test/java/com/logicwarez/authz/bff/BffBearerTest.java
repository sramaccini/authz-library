package com.logicwarez.authz.bff;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

import com.logicwarez.authz.session.AuthorizationResolver;
import com.logicwarez.authz.session.PersonalAccessTokenVerifier;
import com.logicwarez.authz.session.SessionContext;
import com.logicwarez.authz.session.TokenAuthentication;
import com.logicwarez.authz.session.UserNotAuthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Accesso con {@code Authorization: Bearer} (authz.bff.bearer): access token dello IAM e token personali, tenant
 * dall'header X-Tenant, niente CSRF, nessuna sessione creata, mai cookie e token insieme.
 */
@SpringBootTest(classes = BffBearerTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"authz.bff.bearer.enabled=true", "authz.bff.bearer.rate-limit.enabled=false"})
@TestPropertySource(locations = "classpath:bff-test.properties")
class BffBearerTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    static final String PERSONAL_TOKEN = PersonalAccessTokenVerifier.PREFIX + "valido";
    static final List<String> RESOLVED = new CopyOnWriteArrayList<>();

    @Autowired
    Environment environment;

    private final HttpClient http = HttpClient.newHttpClient();
    private String base;

    @BeforeEach
    void setUp() {
        base = "http://localhost:" + environment.getProperty("local.server.port");
        RESOLVED.clear();
    }

    @Test
    void tokenDelloIamConIPermessiDelTenant() throws Exception {
        HttpResponse<String> r = get("/api/whoami", "Authorization", "Bearer " + TestTokens.token("anna.bianchi"));
        assertThat(r.statusCode()).isEqualTo(200);
        JsonNode body = JSON.readTree(r.body());
        assertThat(body.get("username").asString()).isEqualTo("anna.bianchi");
        assertThat(body.get("name").asString()).isEqualTo("Nome anna.bianchi");
        assertThat(body.get("tenant").asString()).isEqualTo("TENANT_A");
        assertThat(body.get("client").asString()).isEqualTo("tools");
        assertThat(body.get("permissions").toString()).isEqualTo("[\"demo.item.read\"]");
        assertThat(r.headers().firstValue("X-Permissions-Version")).isPresent();
        assertThat(r.headers().allValues("Set-Cookie")).as("nessuna sessione").noneMatch(c -> c.startsWith("SESSION"));
        assertThat(RESOLVED).as("risolto senza ricordare il tenant").containsExactly("token:anna.bianchi:null");
    }

    @Test
    void tenantDallHeader() throws Exception {
        String token = "Bearer " + TestTokens.token("anna.bianchi");
        HttpResponse<String> r = get("/api/whoami", "Authorization", token, "X-Tenant", "TENANT_B");
        assertThat(JSON.readTree(r.body()).get("tenant").asString()).isEqualTo("TENANT_B");
        assertThat(get("/api/whoami", "Authorization", token, "X-Tenant", "TENANT_X").statusCode()).isEqualTo(403);
    }

    @Test
    void scrittureSenzaCsrf() throws Exception {
        HttpResponse<String> r = send("POST", "/api/write", "Authorization", "Bearer " + TestTokens.token("anna.bianchi"),
                "Origin", "https://tool.invalid");
        assertThat(r.statusCode()).isEqualTo(200);
    }

    @Test
    void tokenNonValidiScadutiOUtentiSconosciuti() throws Exception {
        HttpResponse<String> invalid = get("/api/whoami", "Authorization", "Bearer abc.def.ghi");
        assertThat(invalid.statusCode()).isEqualTo(401);
        assertThat(invalid.headers().firstValue("WWW-Authenticate")).hasValue("Bearer error=\"invalid_token\"");
        assertThat(get("/api/whoami", "Authorization",
                "Bearer " + TestTokens.token("anna.bianchi", Instant.now().minusSeconds(600))).statusCode())
                .isEqualTo(401);
        assertThat(get("/api/whoami", "Authorization", "Bearer " + TestTokens.token("sconosciuto")).statusCode())
                .isEqualTo(403);
    }

    @Test
    void maiCookieETokenInsieme() throws Exception {
        assertThat(get("/api/whoami", "Authorization", "Bearer " + TestTokens.token("anna.bianchi"),
                "Cookie", "SESSION=qualcosa").statusCode()).isEqualTo(400);
    }

    @Test
    void fuoriDaiPercorsiIlTokenEIgnorato() throws Exception {
        assertThat(get("/bff/user", "Authorization", "Bearer " + TestTokens.token("anna.bianchi")).statusCode())
                .isEqualTo(401);
    }

    @Test
    void tokenPersonale() throws Exception {
        HttpResponse<String> r = get("/api/whoami", "Authorization", "Bearer " + PERSONAL_TOKEN);
        assertThat(r.statusCode()).isEqualTo(200);
        assertThat(JSON.readTree(r.body()).get("client").asString())
                .isEqualTo(TokenAuthentication.PERSONAL_ACCESS_TOKEN);
        assertThat(get("/api/whoami", "Authorization", "Bearer " + PersonalAccessTokenVerifier.PREFIX + "revocato")
                .statusCode()).isEqualTo(401);
    }

    private HttpResponse<String> get(String path, String... headers) throws Exception {
        return send("GET", path, headers);
    }

    private HttpResponse<String> send(String method, String path, String... headers) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                .method(method, HttpRequest.BodyPublishers.noBody());
        for (int i = 0; i < headers.length; i += 2) {
            request.header(headers[i], headers[i + 1]);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @EnableSpringHttpSession
    @Import(TestApp.Api.class)
    static class TestApp {

        @Bean
        MapSessionRepository sessionRepository() {
            return new MapSessionRepository(new java.util.concurrent.ConcurrentHashMap<>());
        }

        @Bean(BffAutoConfiguration.BEARER_DECODER)
        JwtDecoder authzBearerJwtDecoder() {
            return TestTokens.decoder();
        }

        @Bean
        PersonalAccessTokenVerifier personalTokens() {
            return token -> token.equals(PERSONAL_TOKEN)
                    ? Optional.of(new PersonalAccessTokenVerifier.Owner("anna.bianchi", Instant.now().plusSeconds(60)))
                    : Optional.empty();
        }

        @Bean
        AuthorizationResolver resolver() {
            List<SessionContext.Tenant> tenants = List.of(new SessionContext.Tenant("TENANT_A", "Sede A"),
                    new SessionContext.Tenant("TENANT_B", "Sede B"));
            return new AuthorizationResolver() {
                @Override
                public Resolved resolve(String username, String tenant) {
                    RESOLVED.add("login:" + username + ":" + tenant);
                    return resolved(username, tenant);
                }

                @Override
                public Resolved resolveForToken(String username, String tenant) {
                    RESOLVED.add("token:" + username + ":" + tenant);
                    return resolved(username, tenant);
                }

                private Resolved resolved(String username, String tenant) {
                    if (!username.equals("anna.bianchi")) {
                        throw new UserNotAuthorizedException("Utente sconosciuto");
                    }
                    return switch (tenant == null ? "TENANT_A" : tenant) {
                        case "TENANT_A" -> new Resolved(username, "anna@example.org", "TENANT_A", tenants,
                                List.of("VIEWER"), List.of("demo.item.read"));
                        case "TENANT_B" -> new Resolved(username, "anna@example.org", "TENANT_B", tenants,
                                List.of("EDITOR"), List.of("demo.item.edit"));
                        default -> throw new UserNotAuthorizedException("Nessun ruolo sul tenant");
                    };
                }
            };
        }

        @Bean
        SecurityFilterChain security(HttpSecurity http) {
            http.with(BffConfigurer.bff(), Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers(BffControllers.PUBLIC_PATHS).permitAll()
                    .anyRequest().authenticated());
            return http.build();
        }

        @RestController
        static class Api {

            @GetMapping("/api/whoami")
            Map<String, Object> whoami(@AuthenticationPrincipal SessionContext session, Authentication authentication) {
                return Map.of("username", session.username(), "name", session.name(), "tenant", session.tenantId(),
                        "permissions", session.permissions(),
                        "client", ((TokenAuthentication) authentication).client());
            }

            @PostMapping("/api/write")
            ResponseEntity<Void> write(HttpServletRequest request) {
                return ResponseEntity.ok().build();
            }
        }
    }
}
