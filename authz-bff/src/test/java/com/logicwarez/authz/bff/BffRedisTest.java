package com.logicwarez.authz.bff;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.logicwarez.authz.session.AuthorizationResolver;
import com.logicwarez.authz.session.SessionContext;
import jakarta.servlet.http.HttpServletRequest;
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
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Il BFF con le sessioni su un Redis vero, configurato come l'applicazione di esempio (repository indicizzato):
 * sessione salvata e riletta, revoca delle sessioni di un utente, sessione scritta da un'altra versione delle classi.
 * Senza Docker il test viene saltato.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = BffRedisTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.session.data.redis.repository-type=indexed",
                "spring.session.data.redis.namespace=" + BffRedisTest.NAMESPACE})
@TestPropertySource(locations = "classpath:bff-test.properties")
class BffRedisTest {

    static final String NAMESPACE = "authztest";

    @Container
    @ServiceConnection(name = "redis")
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7.4").withExposedPorts(6379);

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @Autowired
    Environment environment;

    @Autowired
    RedisConnectionFactory redis;

    @Autowired
    FindByIndexNameSessionRepository<?> sessions;

    private String base;

    @BeforeEach
    void setUp() {
        base = "http://localhost:" + environment.getProperty("local.server.port");
    }

    @Test
    void sessioneSalvataERilettaDaRedis() throws Exception {
        Browser anna = signIn("anna.bianchi", "demo.item.read");

        HttpResponse<String> user = anna.send("GET", "/bff/user");
        assertThat(user.statusCode()).isEqualTo(200);
        assertThat(JSON.readTree(user.body()).path("username").asString()).isEqualTo("anna.bianchi");
        SessionContext stored = sessions.findById(anna.sessionId()).getAttribute(SessionContext.ATTRIBUTE);
        assertThat(stored.permissions()).containsExactly("demo.item.read");
    }

    @Test
    void revocaDiTutteLeSessioniDiUnUtente() throws Exception {
        Browser office = signIn("mario.rossi", "demo.item.read");
        Browser home = signIn("mario.rossi", "demo.item.read");
        Browser admin = signIn("admin.globale", "authz.session.revokeglobal");
        assertThat(sessions.findByPrincipalName("mario.rossi")).hasSize(2);

        HttpResponse<String> revoked = admin.write("DELETE", "/bff/admin/users/mario.rossi/sessions");
        assertThat(revoked.statusCode()).isEqualTo(200);
        assertThat(JSON.readTree(revoked.body()).path("revoked_sessions").asInt()).isEqualTo(2);

        assertThat(office.send("GET", "/bff/user").statusCode()).isEqualTo(401);
        assertThat(home.send("GET", "/bff/user").statusCode()).isEqualTo(401);
        assertThat(admin.send("GET", "/bff/user").statusCode()).isEqualTo(200);
    }

    @Test
    void sessioneDiUnAltraVersioneContaComeAssente() throws Exception {
        Browser anna = signIn("anna.bianchi", "demo.item.read");

        // Come una sessione scritta prima di un rename del package: l'attributo nomina una classe che non c'e' piu'
        byte[] key = (NAMESPACE + ":sessions:" + anna.sessionId()).getBytes(StandardCharsets.UTF_8);
        byte[] current = ("sessionAttr:" + SessionContext.ATTRIBUTE).getBytes(StandardCharsets.UTF_8);
        byte[] old = "sessionAttr:it.logicware.authz.session.SessionContext".getBytes(StandardCharsets.UTF_8);
        byte[] value = renameClass(new JdkSerializationRedisSerializer().serialize(
                anna.context), SessionContext.class.getName(), SessionContext.class.getName().replaceAll(".$", "X"));
        try (RedisConnection connection = redis.getConnection()) {
            connection.hashCommands().hDel(key, current);
            connection.hashCommands().hSet(key, old, value);
        }

        assertThat(anna.send("GET", "/bff/user").statusCode()).isEqualTo(401);
        HttpResponse<String> login = anna.send("GET", "/bff/login?return=" + "http://app.test/home");
        assertThat(login.statusCode()).isEqualTo(302);
        assertThat(login.headers().firstValue("Location")).hasValueSatisfying(l -> assertThat(l).contains("/oauth2/"));
    }

    private Browser signIn(String username, String permission) throws Exception {
        Browser browser = new Browser();
        HttpResponse<String> r = browser.send("GET", "/test/signin?user=" + username + "&permission=" + permission);
        assertThat(r.statusCode()).isEqualTo(204);
        browser.context = new SessionContext(username, username, username + "@example.org", "TENANT_A",
                List.of(new SessionContext.Tenant("TENANT_A", "Sede A")), List.of("TEST"), List.of(permission),
                Instant.now(), Instant.now().plusSeconds(3600));
        return browser;
    }

    private static byte[] renameClass(byte[] serialized, String from, String to) {
        // Stessa lunghezza: il nome nello stream e' preceduto dalla sua lunghezza
        assertThat(to).hasSameSizeAs(from);
        String text = new String(serialized, StandardCharsets.ISO_8859_1);
        return text.replace(from, to).getBytes(StandardCharsets.ISO_8859_1);
    }

    /** Un browser: i propri cookie, redirect non seguiti. */
    private class Browser {

        private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        private final Map<String, String> cookies = new LinkedHashMap<>();
        private SessionContext context;

        String sessionId() {
            return new String(Base64.getDecoder().decode(cookies.get("SESSION")), StandardCharsets.UTF_8);
        }

        HttpResponse<String> write(String method, String path) throws Exception {
            if (!cookies.containsKey("XSRF-TOKEN")) {
                send("GET", "/bff/user");
            }
            return send(method, path, "X-XSRF-TOKEN", cookies.get("XSRF-TOKEN"));
        }

        HttpResponse<String> send(String method, String path, String... headers) throws Exception {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                    .header("Accept", "application/json")
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

    /** BFF con le sessioni di Spring Session Data Redis (autoconfigurazione) e un ingresso di test al posto dello IAM. */
    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(TestApp.SignIn.class)
    static class TestApp {

        @Bean
        AuthorizationResolver resolver() {
            return (username, tenant) -> {
                throw new UnsupportedOperationException("login solo da /test/signin");
            };
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

            /** Quello che fa LoginSuccessHandler dopo lo IAM, compreso l'indice per la revoca. */
            @GetMapping("/test/signin")
            ResponseEntity<Void> signIn(@RequestParam String user, @RequestParam String permission,
                                        HttpServletRequest request) {
                Instant now = Instant.now();
                var session = request.getSession();
                session.setAttribute(SessionContext.ATTRIBUTE, new SessionContext(user, user, user + "@example.org",
                        "TENANT_A", List.of(new SessionContext.Tenant("TENANT_A", "Sede A")), List.of("TEST"),
                        List.of(permission), now, now.plusSeconds(3600)));
                session.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, user);
                return ResponseEntity.noContent().build();
            }
        }
    }
}
