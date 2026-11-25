package com.logicwarez.authz.bff;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.logicwarez.authz.session.AuthorizationResolver;
import com.logicwarez.authz.session.SessionContext;
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
 * Ruoli operativi (contracts/bff.yaml 0.6.0 di Quadrava, ADR-28) provati via HTTP come li prova il kit
 * {@code npm run conformance:bff}: il ruolo della sessione, {@code POST /bff/role}, i permessi di {@code /authz} per
 * il ruolo attivo e l'header {@code X-Active-Role} verso l'applicazione.
 */
@SpringBootTest(classes = BffRolesTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "classpath:bff-test.properties")
class BffRolesTest {

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

    @Test
    void utenteConIRuoliOperativiEQuelloAttivo() throws Exception {
        signIn("anna.bianchi");
        JsonNode user = json(send("GET", "/bff/user", null));
        assertThat(user.get("currentRole").asString()).isEqualTo("APPROVER");
        assertThat(user.get("operationalRoles").toString())
                .isEqualTo("[{\"id\":\"APPROVER\",\"label\":\"Approvatore\"},{\"id\":\"CLERK\",\"label\":\"Addetto\"}]");
        assertThat(user.get("roles").toString()).isEqualTo("[\"APPROVER\",\"CLERK\",\"USER\"]");
        assertThat(json(send("GET", "/authz/capabilities?app=demo", null)).get("permissions").toString())
                .isEqualTo("[\"orders.order.approve\",\"profile.profile.read\"]");
    }

    @Test
    void cambioDiRuolo() throws Exception {
        signIn("anna.bianchi");
        HttpResponse<String> before = send("GET", "/authz/capabilities?app=demo", null);

        HttpResponse<String> r = write("POST", "/bff/role", "{\"role\":\"CLERK\"}");
        assertThat(r.statusCode()).isEqualTo(204);
        HttpResponse<String> after = send("GET", "/authz/capabilities?app=demo", null);
        assertThat(json(after).get("permissions").toString())
                .isEqualTo("[\"orders.order.create\",\"profile.profile.read\"]");
        String version = json(after).get("version").asString();
        assertThat(version).isNotEqualTo(json(before).get("version").asString());
        assertThat(r.headers().allValues("X-Permissions-Version")).containsExactly(version);
        JsonNode user = json(send("GET", "/bff/user", null));
        assertThat(user.get("currentRole").asString()).isEqualTo("CLERK");
        assertThat(user.get("currentTenant").asString()).as("il tenant resta").isEqualTo("TENANT_A");
    }

    @Test
    void cambioDiRuoloRifiutato() throws Exception {
        signIn("anna.bianchi");
        assertThat(send("GET", "/bff/role", null).statusCode()).isGreaterThanOrEqualTo(400);
        assertThat(send("POST", "/bff/role", "{\"role\":\"CLERK\"}").statusCode()).isEqualTo(403);
        HttpResponse<String> base = write("POST", "/bff/role", "{\"role\":\"USER\"}");
        assertThat(base.statusCode()).as("un ruolo di base non si sceglie").isEqualTo(404);
        assertThat(json(base).get("status").asInt()).isEqualTo(404);
        assertThat(write("POST", "/bff/role", "{\"role\":\"ADMIN\"}").statusCode()).isEqualTo(404);
        assertThat(write("POST", "/bff/role", "{\"role\":7}").statusCode()).isEqualTo(400);
        assertThat(write("POST", "/bff/role", "{\"role\":\"CLERK\",\"extra\":true}").statusCode()).isEqualTo(400);
        assertThat(write("POST", "/bff/role", "[\"CLERK\"]").statusCode()).isEqualTo(400);
        assertThat(write("POST", "/bff/role", "{not json").statusCode()).isEqualTo(400);
        assertThat(json(send("GET", "/bff/user", null)).get("currentRole").asString()).isEqualTo("APPROVER");
    }

    @Test
    void ilRuoloMandatoDallaPaginaNonCambiaIPermessi() throws Exception {
        signIn("anna.bianchi");
        String own = json(send("GET", "/authz/capabilities?app=demo", null)).toString();
        assertThat(json(send("GET", "/authz/capabilities?app=demo&role=CLERK", null, "X-Active-Role", "CLERK"))
                .toString()).isEqualTo(own);
        JsonNode results = json(write("POST", "/authz/check",
                "{\"role\":\"CLERK\",\"checks\":[{\"permission\":\"orders.order.create\"}]}", "X-Active-Role", "CLERK"))
                .get("results");
        assertThat(results.get(0).get("allowed").asBoolean()).isFalse();
    }

    @Test
    void xActiveRoleEQuelloDellaSessioneMaiQuelloDellaPagina() throws Exception {
        signIn("anna.bianchi");
        assertThat(send("GET", "/api/role", null, "X-Active-Role", "CLERK").body()).isEqualTo("APPROVER|APPROVER|1");
        write("POST", "/bff/role", "{\"role\":\"CLERK\"}");
        assertThat(send("GET", "/api/role", null).body()).isEqualTo("CLERK|CLERK|1");
    }

    @Test
    void cambioDiTenantTieneIlRuoloSeLUtenteLoHa() throws Exception {
        signIn("anna.bianchi");
        write("POST", "/bff/role", "{\"role\":\"CLERK\"}");
        assertThat(write("POST", "/bff/tenant", "{\"tenant\":\"TENANT_B\"}").statusCode()).isEqualTo(204);
        JsonNode user = json(send("GET", "/bff/user", null));
        assertThat(user.get("currentTenant").asString()).isEqualTo("TENANT_B");
        assertThat(user.get("currentRole").asString()).isEqualTo("CLERK");
    }

    @Test
    void senzaRuoliOperativiNienteCampiNeHeader() throws Exception {
        signIn("carla.verdi");
        JsonNode user = json(send("GET", "/bff/user", null));
        assertThat(user.has("operationalRoles")).isFalse();
        assertThat(user.has("currentRole")).isFalse();
        assertThat(write("POST", "/bff/role", "{\"role\":\"USER\"}").statusCode()).isEqualTo(404);
        assertThat(send("GET", "/api/role", null, "X-Active-Role", "ADMIN").body()).isEqualTo("-|-|0");
    }

    // --- Supporto ---

    private void signIn(String user) throws Exception {
        assertThat(send("GET", "/test/signin?user=" + user, null).statusCode()).isEqualTo(204);
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

    /**
     * Applicazione minima: BFF con sessioni in memoria e un resolver finto. anna.bianchi ha un ruolo di base e due
     * operativi su TENANT_A, e CLERK anche su TENANT_B; carla.verdi solo il ruolo di base.
     */
    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(TestApp.SignIn.class)
    @EnableSpringHttpSession
    static class TestApp {

        private static final Map<String, List<String>> PERMISSIONS = Map.of(
                "USER", List.of("profile.profile.read"),
                "CLERK", List.of("orders.order.create"),
                "APPROVER", List.of("orders.order.approve"));
        private static final Map<String, String> LABELS = Map.of("CLERK", "Addetto", "APPROVER", "Approvatore");

        @Bean
        MapSessionRepository sessionRepository() {
            return new MapSessionRepository(new java.util.concurrent.ConcurrentHashMap<>());
        }

        @Bean
        AuthorizationResolver resolver() {
            List<SessionContext.Tenant> tenants = List.of(new SessionContext.Tenant("TENANT_A", "Sede A"),
                    new SessionContext.Tenant("TENANT_B", "Sede B"));
            return new AuthorizationResolver() {
                @Override
                public Resolved resolve(String username, String tenant) {
                    return resolve(username, tenant, null);
                }

                @Override
                public Resolved resolve(String username, String tenant, String preferredRole) {
                    String t = tenant == null ? "TENANT_A" : tenant;
                    if (!t.equals("TENANT_A") && !t.equals("TENANT_B")) {
                        throw new UserNotAuthorizedException("Nessun ruolo sul tenant");
                    }
                    List<String> operational = username.equals("carla.verdi") ? List.of()
                            : t.equals("TENANT_A") ? List.of("APPROVER", "CLERK") : List.of("CLERK");
                    String active = operational.isEmpty() ? null
                            : preferredRole != null && operational.contains(preferredRole) ? preferredRole
                            : operational.getFirst();
                    List<String> roles = new java.util.ArrayList<>(operational);
                    roles.add("USER");
                    Collections.sort(roles);
                    List<String> permissions = roles.stream()
                            .filter(r -> active == null || r.equals("USER") || r.equals(active))
                            .flatMap(r -> PERMISSIONS.get(r).stream()).sorted().toList();
                    return new Resolved(username, username + "@example.org", t, tenants, roles, permissions,
                            operational.stream().map(r -> new SessionContext.Role(r, LABELS.get(r))).toList(), active);
                }
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
                        now, now.plusSeconds(3600), r.operationalRoles(), r.currentRole()));
                return org.springframework.http.ResponseEntity.noContent().build();
            }

            /** X-Active-Role come lo vede l'applicazione: getHeader, getHeaders e quante volte in getHeaderNames. */
            @GetMapping("/api/role")
            String role(HttpServletRequest request) {
                String one = request.getHeader("x-active-role");
                List<String> all = Collections.list(request.getHeaders("X-Active-Role"));
                long named = Collections.list(request.getHeaderNames()).stream()
                        .filter(n -> n.equalsIgnoreCase("X-Active-Role")).count();
                return (one == null ? "-" : one) + "|" + (all.isEmpty() ? "-" : String.join(",", all)) + "|" + named;
            }
        }
    }
}
