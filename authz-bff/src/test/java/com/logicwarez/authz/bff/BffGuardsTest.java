package com.logicwarez.authz.bff;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.logicwarez.authz.session.AuthorizationResolver;
import com.logicwarez.authz.session.SessionContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Login recente prima delle azioni sensibili (authz.bff.recent-login), max_age verso lo IAM e limite di frequenza
 * delle sessioni (authz.bff.session-rate-limit), su un Redis vero. Il login passa dal LoginSuccessHandler vero con un
 * ID token costruito dal test. Senza Docker il test viene saltato.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = BffGuardsTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.session.data.redis.namespace=authzguards",
                "authz.bff.recent-login.max-age=15m",
                "authz.bff.recent-login.paths=/api/admin/**,POST /api/me/tokens",
                "authz.bff.session-rate-limit.enabled=true",
                "authz.bff.session-rate-limit.max-requests=5",
                "authz.bff.session-rate-limit.window=1m"})
@TestPropertySource(locations = "classpath:bff-test.properties")
class BffGuardsTest {

    @Container
    @ServiceConnection(name = "redis")
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7.4").withExposedPorts(6379);

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @Autowired
    Environment environment;

    private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    private String base;

    @BeforeEach
    void setUp() {
        base = "http://localhost:" + environment.getProperty("local.server.port");
    }

    // --- Login recente ---

    @Test
    void azioniSensibiliSoloConUnLoginRecente() throws Exception {
        Browser old = signIn("vecchio." + System.nanoTime(), Instant.now().minusSeconds(3600));
        HttpResponse<String> denied = old.send("GET", "/api/admin/settings");
        assertThat(denied.statusCode()).isEqualTo(401);
        assertThat(denied.headers().firstValue("Content-Type")).hasValue("application/problem+json;charset=UTF-8");
        JsonNode problem = JSON.readTree(denied.body());
        assertThat(problem.path("type").asString()).isEqualTo("urn:problem:authz:recent-login-required");
        assertThat(problem.path("title").asString()).isEqualTo("Recent login required");
        assertThat(problem.path("maxAge").asInt()).isEqualTo(900);
        assertThat(old.send("GET", "/bff/user").statusCode()).as("la sessione resta valida").isEqualTo(200);
        assertThat(old.send("GET", "/api/items").statusCode()).as("percorso non sensibile").isEqualTo(200);
        assertThat(old.send("GET", "/api/me/tokens").statusCode()).as("solo POST e' sensibile").isEqualTo(200);
        assertThat(old.write("POST", "/api/me/tokens").statusCode()).isEqualTo(401);

        Browser fresh = signIn("recente." + System.nanoTime(), Instant.now().minusSeconds(60));
        assertThat(fresh.send("GET", "/api/admin/settings").statusCode()).isEqualTo(200);
        assertThat(fresh.write("POST", "/api/me/tokens").statusCode()).isEqualTo(200);

        Browser noClaim = signIn("senzaclaim." + System.nanoTime(), null);
        assertThat(noClaim.send("GET", "/api/admin/settings").statusCode()).as("auth_time = login").isEqualTo(200);
    }

    @Test
    void maxAgeFinoAlloIamAncheConUnaSessioneAperta() throws Exception {
        Browser browser = signIn("riautentica." + System.nanoTime(), Instant.now().minusSeconds(3600));

        HttpResponse<String> plain = browser.send("GET", "/bff/login?return=http://app.test/admin");
        assertThat(plain.headers().firstValue("Location")).as("senza max_age: subito alla pagina")
                .hasValue("http://app.test/admin");

        HttpResponse<String> login = browser.send("GET", "/bff/login?return=http://app.test/admin&max_age=0");
        assertThat(login.statusCode()).isEqualTo(302);
        assertThat(login.headers().firstValue("Location")).hasValueSatisfying(l -> assertThat(l).endsWith("/oauth2/authorization/iam"));
        HttpResponse<String> authorize = browser.send("GET", "/oauth2/authorization/iam");
        assertThat(authorize.statusCode()).isEqualTo(302);
        String location = authorize.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith("http://iam.test/auth?").contains("max_age=0").contains("state=")
                .contains("client_id=bff");

        Browser other = new Browser();
        other.send("GET", "/bff/login");
        assertThat(other.send("GET", "/oauth2/authorization/iam").headers().firstValue("Location").orElseThrow())
                .as("senza max_age niente parametro").doesNotContain("max_age");

        assertThat(browser.send("GET", "/bff/login?max_age=-1").statusCode()).isEqualTo(400);
        assertThat(browser.send("GET", "/bff/login?max_age=abc").statusCode()).isEqualTo(400);
    }

    // --- Limite delle sessioni ---

    @Test
    void oltreIlLimitePerUtente429() throws Exception {
        Browser anna = signIn("limite." + System.nanoTime(), Instant.now());
        for (int i = 0; i < 5; i++) {
            assertThat(anna.send("GET", "/api/items").statusCode()).isEqualTo(200);
        }
        HttpResponse<String> limited = anna.send("GET", "/api/items");
        assertThat(limited.statusCode()).isEqualTo(429);
        assertThat(limited.headers().firstValue("Retry-After")).hasValue("60");
        assertThat(JSON.readTree(limited.body()).path("status").asInt()).isEqualTo(429);
        assertThat(anna.send("GET", "/bff/user").statusCode()).as("/bff/** fuori dal limite").isEqualTo(200);

        Browser same = signIn(anna.username, Instant.now());
        assertThat(same.send("GET", "/api/items").statusCode()).as("per utente, non per sessione").isEqualTo(429);
        Browser other = signIn("altro." + System.nanoTime(), Instant.now());
        assertThat(other.send("GET", "/api/items").statusCode()).isEqualTo(200);
    }

    private Browser signIn(String user, Instant authTime) throws Exception {
        Browser browser = new Browser();
        browser.username = user;
        HttpResponse<String> r = browser.send("GET", "/test/signin?user=" + user
                + (authTime == null ? "" : "&authTime=" + authTime.getEpochSecond()));
        assertThat(r.statusCode()).as(r.body()).isEqualTo(302);
        browser.send("GET", "/bff/user");
        return browser;
    }

    /** Un browser: i propri cookie, redirect non seguiti. */
    private class Browser {

        private final Map<String, String> cookies = new LinkedHashMap<>();
        private String username;

        HttpResponse<String> write(String method, String path) throws Exception {
            return send(method, path, "X-XSRF-TOKEN", cookies.get("XSRF-TOKEN"));
        }

        HttpResponse<String> send(String method, String path, String... headers) throws Exception {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                    .method(method, HttpRequest.BodyPublishers.noBody());
            for (int i = 0; i < headers.length; i += 2) {
                request.header(headers[i], headers[i + 1]);
            }
            if (!cookies.isEmpty()) {
                request.header("Cookie", String.join("; ", cookies.entrySet().stream()
                        .map(e -> e.getKey() + "=" + e.getValue()).toList()));
            }
            HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
            for (String line : response.headers().allValues("Set-Cookie")) {
                String[] pair = line.split(";", 2)[0].split("=", 2);
                if (pair[1].isEmpty() || line.toLowerCase().contains("max-age=0")) {
                    cookies.remove(pair[0]);
                } else {
                    cookies.put(pair[0], pair[1]);
                }
            }
            return response;
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import({TestApp.SignIn.class, TestApp.Api.class})
    static class TestApp {

        @Bean
        AuthorizationResolver resolver() {
            return (username, tenant) -> new AuthorizationResolver.Resolved(username, username + "@example.org",
                    "TENANT_A", List.of(new SessionContext.Tenant("TENANT_A", "Sede A")), List.of("TEST"),
                    List.of("demo.item.read"));
        }

        @Bean
        SecurityFilterChain security(HttpSecurity http) {
            http.with(BffConfigurer.bff(), Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers(BffControllers.PUBLIC_PATHS).permitAll()
                    .requestMatchers("/test/**").permitAll()
                    .anyRequest().authenticated());
            return http.build();
        }

        @RestController
        static class Api {

            @GetMapping({"/api/items", "/api/admin/settings", "/api/me/tokens"})
            ResponseEntity<Void> read() {
                return ResponseEntity.ok().build();
            }

            @PostMapping("/api/me/tokens")
            ResponseEntity<Void> create() {
                return ResponseEntity.ok().build();
            }
        }

        @RestController
        static class SignIn {

            private final LoginSupport.LoginSuccessHandler handler;

            SignIn(LoginSupport.LoginSuccessHandler handler) {
                this.handler = handler;
            }

            /** Il ritorno dallo IAM: LoginSuccessHandler con un ID token con o senza auth_time. */
            @GetMapping("/test/signin")
            void signIn(@RequestParam String user, @RequestParam(required = false) Long authTime,
                        HttpServletRequest request, HttpServletResponse response) throws IOException {
                Instant now = Instant.now();
                Map<String, Object> claims = new LinkedHashMap<>(Map.of("sub", "sub-" + user,
                        "preferred_username", user, "name", user));
                if (authTime != null) {
                    claims.put("auth_time", authTime);
                }
                OidcIdToken idToken = new OidcIdToken("id-token", now, now.plusSeconds(300), claims);
                request.getSession();
                handler.onAuthenticationSuccess(request, response, new OAuth2AuthenticationToken(
                        new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, idToken, "sub"),
                        AuthorityUtils.NO_AUTHORITIES, "iam"));
            }
        }
    }
}
