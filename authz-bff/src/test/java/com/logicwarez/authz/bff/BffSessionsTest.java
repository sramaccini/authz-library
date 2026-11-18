package com.logicwarez.authz.bff;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Sessioni dell'utente e back-channel logout su un Redis vero (repository indicizzato). Il login passa dal
 * LoginSuccessHandler vero con un utente OIDC costruito dal test al posto dello IAM. Senza Docker il test viene saltato.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = BffSessionsTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.session.data.redis.repository-type=indexed",
                "spring.session.data.redis.namespace=authzsessions",
                "authz.bff.backchannel-logout.enabled=true"})
@org.springframework.test.context.TestPropertySource(locations = "classpath:bff-test.properties")
class BffSessionsTest {

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

    // --- Sessioni dell'utente ---

    @Test
    void elencoDelleProprieSessioni() throws Exception {
        String user = "elenco." + System.nanoTime();
        Browser office = signIn(user, "sid-a", "Firefox ufficio", "203.0.113.7");
        Browser home = signIn(user, "sid-b", "Safari casa", "198.51.100.9");

        HttpResponse<String> r = office.send("GET", "/bff/sessions");
        assertThat(r.statusCode()).isEqualTo(200);
        JsonNode list = JSON.readTree(r.body());
        assertThat(list).hasSize(2);
        assertThat(r.body()).as("mai l'id della sessione").doesNotContain(office.sessionId(), home.sessionId());
        JsonNode current = find(list, "current", "true");
        assertThat(current.path("userAgent").asString()).isEqualTo("Firefox ufficio");
        assertThat(current.path("ipAddress").asString()).isEqualTo("203.0.113.7");
        assertThat(current.path("tenant").asString()).isEqualTo("TENANT_A");
        assertThat(current.path("id").asString()).matches("[0-9a-f]{32}");
        assertThat(current.path("createdAt").asString()).isNotEmpty();
        assertThat(find(list, "current", "false").path("userAgent").asString()).isEqualTo("Safari casa");
    }

    @Test
    void chiusuraDiUnaSessioneODiTutteLeAltre() throws Exception {
        String user = "chiusura." + System.nanoTime();
        Browser office = signIn(user, "sid-1", "Firefox", "203.0.113.1");
        Browser home = signIn(user, "sid-2", "Safari", "203.0.113.2");
        Browser phone = signIn(user, "sid-3", "Mobile", "203.0.113.3");
        String homeId = find(JSON.readTree(office.send("GET", "/bff/sessions").body()), "userAgent", "Safari")
                .path("id").asString();

        assertThat(office.send("DELETE", "/bff/sessions/" + homeId).statusCode()).as("senza CSRF").isEqualTo(403);
        assertThat(office.write("DELETE", "/bff/sessions/" + homeId).statusCode()).isEqualTo(204);
        assertThat(home.send("GET", "/bff/user").statusCode()).isEqualTo(401);
        assertThat(office.write("DELETE", "/bff/sessions/" + homeId).statusCode()).isEqualTo(404);
        assertThat(office.write("DELETE", "/bff/sessions/not-an-id").statusCode()).isEqualTo(400);

        assertThat(office.write("DELETE", "/bff/sessions").statusCode()).isEqualTo(204);
        assertThat(phone.send("GET", "/bff/user").statusCode()).isEqualTo(401);
        assertThat(office.send("GET", "/bff/user").statusCode()).as("la sessione corrente resta").isEqualTo(200);
        assertThat(JSON.readTree(office.send("GET", "/bff/sessions").body())).hasSize(1);
    }

    @Test
    void sessioniDiUnUtenteVisteDallAmministratore() throws Exception {
        String user = "vista." + System.nanoTime();
        signIn(user, "sid-x", "Firefox", "203.0.113.4");
        signIn(user, "sid-y", "Safari", "203.0.113.5");
        Browser admin = signIn("admin.globale", "sid-admin", "Edge", "203.0.113.6");
        Browser other = signIn("altro." + System.nanoTime(), "sid-z", "Edge", "203.0.113.6");

        HttpResponse<String> r = admin.send("GET", "/bff/admin/users/" + user + "/sessions");
        assertThat(r.statusCode()).isEqualTo(200);
        JsonNode list = JSON.readTree(r.body());
        assertThat(list).hasSize(2);
        assertThat(list.get(0).path("current").asBoolean()).isFalse();
        assertThat(other.send("GET", "/bff/admin/users/" + user + "/sessions").statusCode()).isEqualTo(403);
    }

    // --- Back-channel logout ---

    @Test
    void logoutDalloIamPerSidOPerSub() throws Exception {
        String user = "iam." + System.nanoTime();
        String sub = "sub-" + user;
        Browser first = signIn(user, sub, "sid-p", "Firefox", "203.0.113.8");
        Browser second = signIn(user, sub, "sid-q", "Safari", "203.0.113.9");

        HttpResponse<String> bySid = backChannel(TestTokens.sign(TestTokens.logoutClaims(sub, "sid-p").build()));
        assertThat(bySid.statusCode()).isEqualTo(200);
        assertThat(bySid.headers().firstValue("Cache-Control")).hasValueSatisfying(v -> assertThat(v).contains("no-store"));
        assertThat(first.send("GET", "/bff/user").statusCode()).isEqualTo(401);
        assertThat(second.send("GET", "/bff/user").statusCode()).as("altra sessione dello IAM").isEqualTo(200);

        Browser third = signIn(user, sub, "sid-r", "Mobile", "203.0.113.10");
        assertThat(backChannel(TestTokens.sign(TestTokens.logoutClaims(sub, null).build())).statusCode()).isEqualTo(200);
        assertThat(second.send("GET", "/bff/user").statusCode()).as("tutte le sessioni del sub").isEqualTo(401);
        assertThat(third.send("GET", "/bff/user").statusCode()).isEqualTo(401);

        assertThat(backChannel(TestTokens.sign(TestTokens.logoutClaims("sconosciuto", "sid-ignoto").build())).statusCode())
                .as("nessuna sessione: va bene lo stesso").isEqualTo(200);
    }

    @Test
    void logoutTokenNonValidi() throws Exception {
        String user = "rifiuto." + System.nanoTime();
        Browser browser = signIn(user, "sub-" + user, "sid-k", "Firefox", "203.0.113.11");

        String valid = TestTokens.sign(TestTokens.logoutClaims("sub-" + user, "sid-k").build());
        List<String> invalid = List.of(
                TestTokens.signWithOtherKey(TestTokens.logoutClaims("sub-" + user, "sid-k").build()),
                TestTokens.sign(TestTokens.logoutClaims("sub-" + user, "sid-k").audience("altro-client").build()),
                TestTokens.sign(TestTokens.logoutClaims("sub-" + user, "sid-k").issuer("https://altro.test").build()),
                TestTokens.sign(TestTokens.logoutClaims("sub-" + user, "sid-k").claim("events", Map.of()).build()),
                TestTokens.sign(TestTokens.logoutClaims("sub-" + user, "sid-k").claim("nonce", "n").build()),
                TestTokens.sign(TestTokens.logoutClaims(null, null).build()),
                TestTokens.sign(TestTokens.logoutClaims("sub-" + user, "sid-k")
                        .expirationTime(java.util.Date.from(Instant.now().minusSeconds(600))).build()),
                "non.un.jwt");
        for (String token : invalid) {
            HttpResponse<String> r = backChannel(token);
            assertThat(r.statusCode()).as(token).isEqualTo(400);
            assertThat(JSON.readTree(r.body()).path("error").asString()).isEqualTo("invalid_request");
        }
        assertThat(post("/bff/backchannel-logout", "").statusCode()).as("senza logout_token").isEqualTo(400);
        assertThat(browser.send("GET", "/bff/user").statusCode()).isEqualTo(200);

        assertThat(backChannel(valid).statusCode()).isEqualTo(200);
        assertThat(backChannel(valid).statusCode()).as("stesso jti due volte").isEqualTo(400);
        assertThat(browser.send("GET", "/bff/user").statusCode()).isEqualTo(401);
    }

    private HttpResponse<String> backChannel(String token) throws Exception {
        return post("/bff/backchannel-logout", "logout_token=" + URLEncoder.encode(token, StandardCharsets.UTF_8));
    }

    private HttpResponse<String> post(String path, String form) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(base + path))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static JsonNode find(JsonNode list, String field, String value) {
        for (JsonNode node : list) {
            if (node.path(field).asString().equals(value)) {
                return node;
            }
        }
        throw new AssertionError("Nessuna sessione con " + field + "=" + value + " in " + list);
    }

    private Browser signIn(String user, String sid, String agent, String ip) throws Exception {
        return signIn(user, "sub-" + user, sid, agent, ip);
    }

    private Browser signIn(String user, String sub, String sid, String agent, String ip) throws Exception {
        Browser browser = new Browser(agent, ip);
        HttpResponse<String> r = browser.send("GET", "/test/signin?user=" + user + "&sub=" + sub + "&sid=" + sid);
        assertThat(r.statusCode()).as(r.body()).isEqualTo(302);
        assertThat(browser.send("GET", "/bff/user").statusCode()).isEqualTo(200);
        return browser;
    }

    /** Un browser: i propri cookie, il proprio user agent e IP (X-Forwarded-For), redirect non seguiti. */
    private class Browser {

        private final Map<String, String> cookies = new LinkedHashMap<>();
        private final String agent;
        private final String ip;

        Browser(String agent, String ip) {
            this.agent = agent;
            this.ip = ip;
        }

        String sessionId() {
            return new String(java.util.Base64.getDecoder().decode(cookies.get("SESSION")), StandardCharsets.UTF_8);
        }

        HttpResponse<String> write(String method, String path) throws Exception {
            return send(method, path, "X-XSRF-TOKEN", cookies.get("XSRF-TOKEN"));
        }

        HttpResponse<String> send(String method, String path, String... headers) throws Exception {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                    .header("User-Agent", agent).header("X-Forwarded-For", ip)
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
    @Import(TestApp.SignIn.class)
    static class TestApp {

        @Bean(BffAutoConfiguration.LOGOUT_DECODER)
        JwtDecoder authzLogoutTokenDecoder() {
            return TestTokens.logoutDecoder();
        }

        @Bean
        AuthorizationResolver resolver() {
            return (username, tenant) -> new AuthorizationResolver.Resolved(username, username + "@example.org",
                    "TENANT_A", List.of(new SessionContext.Tenant("TENANT_A", "Sede A")), List.of("TEST"),
                    List.of(username.equals("admin.globale") ? "authz.session.revokeglobal" : "demo.item.read"));
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
        static class SignIn {

            private final LoginSupport.LoginSuccessHandler handler;

            SignIn(LoginSupport.LoginSuccessHandler handler) {
                this.handler = handler;
            }

            /** Il ritorno dallo IAM: LoginSuccessHandler con un utente OIDC con sub e sid. */
            @GetMapping("/test/signin")
            void signIn(@RequestParam String user, @RequestParam String sub, @RequestParam String sid,
                        HttpServletRequest request, HttpServletResponse response) throws IOException {
                Instant now = Instant.now();
                OidcIdToken idToken = new OidcIdToken("id-token", now, now.plusSeconds(300),
                        Map.of("sub", sub, "sid", sid, "preferred_username", user, "name", user));
                var principal = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, idToken, "sub");
                request.getSession();
                handler.onAuthenticationSuccess(request, response,
                        new OAuth2AuthenticationToken(principal, AuthorityUtils.NO_AUTHORITIES, "iam"));
            }
        }
    }
}
