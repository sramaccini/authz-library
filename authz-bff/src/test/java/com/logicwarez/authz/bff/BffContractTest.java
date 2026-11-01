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
import java.util.stream.IntStream;

import com.logicwarez.authz.session.AuthorizationResolver;
import com.logicwarez.authz.session.SessionContext;
import com.logicwarez.authz.session.UserNotAuthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Le regole di contracts/bff.yaml e contracts/authz.yaml di Quadrava, provate via HTTP come le prova il kit
 * {@code npm run conformance:bff}: server vero, cookie gestiti a mano, redirect non seguiti.
 */
@SpringBootTest(classes = BffContractTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "classpath:bff-test.properties")
class BffContractTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @Autowired
    private Environment environment;

    private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    private final Map<String, String> cookies = new LinkedHashMap<>();
    private String base;

    @BeforeEach
    void setUp() {
        base = "http://localhost:" + environment.getProperty("local.server.port");
    }

    // --- Regole di ogni chiamata ---

    @Test
    void senzaSessione401ECookieCsrfLeggibile() throws Exception {
        HttpResponse<String> r = send("GET", "/bff/user", null);
        assertThat(r.statusCode()).isEqualTo(401);
        String csrf = r.headers().allValues("Set-Cookie").stream()
                .filter(c -> c.startsWith("XSRF-TOKEN=")).findFirst().orElseThrow();
        assertThat(csrf.toLowerCase()).doesNotContain("httponly");
    }

    @Test
    void scritturaSenzaTokenCsrf403() throws Exception {
        signIn();
        assertThat(send("POST", "/logout", null).statusCode()).isEqualTo(403);
        assertThat(send("POST", "/logout", null, "X-XSRF-TOKEN", "sbagliato").statusCode()).isEqualTo(403);
        assertThat(send("GET", "/bff/user", null).statusCode()).isEqualTo(200);
    }

    @Test
    void scritturaDaOrigineEstranea403AncheConToken() throws Exception {
        signIn();
        assertThat(write("POST", "/logout", null, "Origin", "https://evil.invalid").statusCode()).isEqualTo(403);
        assertThat(write("POST", "/logout", null, "Origin", "http://app.test").statusCode()).isEqualTo(200);
    }

    @Test
    void versioneDeiPermessiSuOgniRispostaAutenticata() throws Exception {
        signIn();
        HttpResponse<String> r = send("GET", "/bff/user", null);
        assertThat(r.headers().firstValue("X-Permissions-Version")).isPresent();
    }

    @Test
    void percorsoInesistenteConSessione404() throws Exception {
        signIn();
        assertThat(send("GET", "/api/inesistente", null).statusCode()).isEqualTo(404);
    }

    @Test
    void rispostaAsincronaConSessione() throws Exception {
        signIn();
        HttpResponse<String> r = send("GET", "/api/async", null);
        assertThat(r.statusCode()).isEqualTo(200);
        assertThat(r.body()).isEqualTo("ok");
    }

    // --- Login ---

    @Test
    void loginConPaginaDelleApplicazioniVaAlloIam() throws Exception {
        HttpResponse<String> r = send("GET", "/bff/login?return=" + encode("http://app.test/board?id=7"), null);
        assertThat(r.statusCode()).isEqualTo(302);
        assertThat(r.headers().firstValue("Location")).hasValue("/oauth2/authorization/iam");
    }

    @Test
    void loginConPaginaEstranea400Problem() throws Exception {
        for (String url : List.of("https://not-an-application.invalid/", "http://user@app.test/", "javascript:alert(1)",
                "//app.test/", "http://app.test.evil.invalid/")) {
            HttpResponse<String> r = send("GET", "/bff/login?return=" + encode(url), null);
            assertThat(r.statusCode()).as(url).isEqualTo(400);
            assertThat(r.headers().firstValue("Content-Type")).hasValue("application/problem+json");
            assertThat(json(r).get("status").asInt()).isEqualTo(400);
        }
    }

    @Test
    void loginAccettaLOriginePubblicaDelBffDietroUnProxy() throws Exception {
        assertThat(send("GET", "/bff/login?return=" + encode(base + "/page"), null).statusCode()).isEqualTo(302);
        HttpResponse<String> proxied = send("GET", "/bff/login?return=" + encode("https://public.example/page"), null,
                "X-Forwarded-Host", "public.example", "X-Forwarded-Proto", "https");
        assertThat(proxied.statusCode()).isEqualTo(302);
        assertThat(send("GET", "/bff/login?return=" + encode("https://public.example/page"), null).statusCode())
                .isEqualTo(400);
    }

    @Test
    void loginConSessioneGiaApertaTornaSubitoAllaPagina() throws Exception {
        signIn();
        HttpResponse<String> r = send("GET", "/bff/login?return=" + encode("http://app.test/board"), null);
        assertThat(r.statusCode()).isEqualTo(302);
        assertThat(r.headers().firstValue("Location")).hasValue("http://app.test/board");
    }

    // --- Utente e logout ---

    @Test
    void utenteDellaSessioneConICampiDelContratto() throws Exception {
        signIn();
        JsonNode user = json(send("GET", "/bff/user", null));
        assertThat(user.get("username").asString()).isEqualTo("anna.bianchi");
        assertThat(user.get("name").asString()).isEqualTo("Anna Bianchi");
        assertThat(user.get("currentTenant").asString()).isEqualTo("TENANT_A");
        assertThat(user.get("tenants").size()).isEqualTo(2);
        assertThat(user.get("tenants").get(1).get("label").asString()).isEqualTo("Sede B");
        assertThat(user.has("permissions")).isFalse();
        assertThat(String.join(" ", user.propertyNames())).doesNotContainIgnoringCase("token");
    }

    @Test
    void logoutChiudeLaSessioneERispondeConRedirect() throws Exception {
        signIn();
        HttpResponse<String> r = write("POST", "/logout", null);
        assertThat(r.statusCode()).isEqualTo(200);
        assertThat(json(r).get("redirect").asString()).isEqualTo("http://app.test/bye");
        assertThat(send("GET", "/bff/user", null).statusCode()).isEqualTo(401);
    }

    // --- Tenant ---

    @Test
    void cambioDiTenant() throws Exception {
        signIn();
        String before = send("GET", "/bff/user", null).headers().firstValue("X-Permissions-Version").orElseThrow();

        assertThat(send("GET", "/bff/tenant", null).statusCode()).isGreaterThanOrEqualTo(400);
        assertThat(send("POST", "/bff/tenant", "{\"tenant\":\"TENANT_B\"}").statusCode()).isEqualTo(403);
        HttpResponse<String> unknown = write("POST", "/bff/tenant", "{\"tenant\":\"NOT_OFFERED\"}");
        assertThat(unknown.statusCode()).isEqualTo(404);
        assertThat(json(unknown).get("status").asInt()).isEqualTo(404);
        assertThat(write("POST", "/bff/tenant", "{}").statusCode()).isEqualTo(400);
        assertThat(write("POST", "/bff/tenant", "{not json").statusCode()).isEqualTo(400);

        assertThat(write("POST", "/bff/tenant", "{\"tenant\":\"TENANT_B\"}").statusCode()).isEqualTo(204);
        HttpResponse<String> after = send("GET", "/bff/user", null);
        assertThat(json(after).get("currentTenant").asString()).isEqualTo("TENANT_B");
        assertThat(after.headers().firstValue("X-Permissions-Version")).isPresent().get().isNotEqualTo(before);
        assertThat(json(send("GET", "/authz/capabilities?app=demo", null)).get("permissions").toString())
                .contains("demo.item.edit");
    }

    // --- Contratto di autorizzazione ---

    @Test
    void capabilities() throws Exception {
        assertThat(send("GET", "/authz/capabilities?app=demo", null).statusCode()).isEqualTo(401);
        signIn();
        HttpResponse<String> r = send("GET", "/authz/capabilities?app=demo", null);
        assertThat(r.statusCode()).isEqualTo(200);
        JsonNode body = json(r);
        assertThat(body.get("permissions").toString()).isEqualTo("[\"demo.item.read\"]");
        assertThat(r.headers().firstValue("X-Permissions-Version")).hasValue(body.get("version").asString());
        assertThat(json(send("GET", "/authz/capabilities?app=demo", null)).get("version").asString())
                .isEqualTo(body.get("version").asString());

        HttpResponse<String> noApp = send("GET", "/authz/capabilities", null);
        assertThat(noApp.statusCode()).isEqualTo(400);
        assertThat(noApp.headers().firstValue("Content-Type")).hasValue("application/problem+json");
    }

    @Test
    void checkInBatch() throws Exception {
        signIn();
        HttpResponse<String> r = write("POST", "/authz/check", """
                {"checks":[{"permission":"conformance.missing.test"},
                           {"permission":"demo.item.read","resource":{"type":"order","id":"7"}}]}""");
        assertThat(r.statusCode()).isEqualTo(200);
        JsonNode results = json(r).get("results");
        assertThat(results.get(0).get("allowed").asBoolean()).isFalse();
        assertThat(results.get(1).get("allowed").asBoolean()).isTrue();
        assertThat(results.get(1).get("resource").get("id").asString()).isEqualTo("7");
        assertThat(r.headers().firstValue("X-Permissions-Version")).isPresent();

        assertThat(write("POST", "/authz/check", "{\"checks\":[{\"permission\":\"Orders.Approve\"}]}").statusCode())
                .isEqualTo(400);
        assertThat(write("POST", "/authz/check", "{}").statusCode()).isEqualTo(400);
        assertThat(write("POST", "/authz/check", "{not json").statusCode()).isEqualTo(400);
        String many = String.join(",", IntStream.range(0, 201).mapToObj(i -> "{\"permission\":\"a.b.c\"}").toList());
        assertThat(write("POST", "/authz/check", "{\"checks\":[" + many + "]}").statusCode()).isEqualTo(400);
    }

    // --- Supporto ---

    private void signIn() throws Exception {
        assertThat(send("GET", "/test/signin?user=anna.bianchi", null).statusCode()).isEqualTo(204);
    }

    /** Scrittura come la fa la pagina: cookie XSRF-TOKEN rimandato nell'header X-XSRF-TOKEN. */
    private HttpResponse<String> write(String method, String path, String body, String... headers) throws Exception {
        if (!cookies.containsKey("XSRF-TOKEN")) {
            send("GET", "/bff/user", null);
        }
        String[] all = new String[headers.length + 2];
        all[0] = "X-XSRF-TOKEN";
        all[1] = cookies.get("XSRF-TOKEN");
        System.arraycopy(headers, 0, all, 2, headers.length);
        return send(method, path, body, all);
    }

    private HttpResponse<String> send(String method, String path, String body, String... headers)
            throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                .header("Accept", "application/json")
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(body));
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
        for (int i = 0; i < headers.length; i += 2) {
            request.header(headers[i], headers[i + 1]);
        }
        if (!cookies.isEmpty()) {
            request.header("Cookie", String.join("; ", cookies.entrySet().stream()
                    .map(e -> e.getKey() + "=" + e.getValue()).toList()));
        }
        HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
        for (String line : response.headers().allValues("Set-Cookie")) {
            String pair = line.split(";", 2)[0];
            int eq = pair.indexOf('=');
            String name = pair.substring(0, eq);
            String value = pair.substring(eq + 1);
            if (value.isEmpty() || line.toLowerCase().contains("max-age=0")) {
                cookies.remove(name);
            } else {
                cookies.put(name, value);
            }
        }
        return response;
    }

    private static JsonNode json(HttpResponse<String> response) {
        return JSON.readTree(response.body());
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** Applicazione minima: BFF con sessioni in memoria, resolver finto e un ingresso di test al posto dello IAM. */
    @SpringBootApplication
    @EnableSpringHttpSession
    static class TestApp {

        @Bean
        MapSessionRepository sessionRepository() {
            return new MapSessionRepository(new java.util.concurrent.ConcurrentHashMap<>());
        }

        @Bean
        AuthorizationResolver resolver() {
            List<SessionContext.Tenant> tenants = List.of(new SessionContext.Tenant("TENANT_A", "Sede A"),
                    new SessionContext.Tenant("TENANT_B", "Sede B"));
            return (username, tenant) -> switch (tenant == null ? "TENANT_A" : tenant) {
                case "TENANT_A" -> new AuthorizationResolver.Resolved(username, username + "@example.org", "TENANT_A",
                        tenants, List.of("VIEWER"), List.of("demo.item.read"));
                case "TENANT_B" -> new AuthorizationResolver.Resolved(username, username + "@example.org", "TENANT_B",
                        tenants, List.of("EDITOR"), List.of("demo.item.read", "demo.item.edit"));
                default -> throw new UserNotAuthorizedException("Nessun ruolo sul tenant");
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

            private final AuthorizationResolver resolver;

            SignIn(AuthorizationResolver resolver) {
                this.resolver = resolver;
            }

            /** Quello che fa LoginSuccessHandler dopo lo IAM. */
            @GetMapping("/test/signin")
            org.springframework.http.ResponseEntity<Void> signIn(@RequestParam String user, HttpServletRequest request) {
                AuthorizationResolver.Resolved r = resolver.resolve(user, null);
                Instant now = Instant.now();
                request.getSession().setAttribute(SessionContext.ATTRIBUTE, new SessionContext(r.username(),
                        "Anna Bianchi", r.email(), r.tenantId(), r.tenants(), r.roles(), r.permissions(),
                        now, now.plusSeconds(3600)));
                return org.springframework.http.ResponseEntity.noContent().build();
            }

            /** Risposta completata con un async dispatch, come gli stream di eventi. */
            @GetMapping("/api/async")
            java.util.concurrent.Callable<String> async() {
                return () -> "ok";
            }
        }
    }
}
