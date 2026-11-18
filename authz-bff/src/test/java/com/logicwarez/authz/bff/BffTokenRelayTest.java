package com.logicwarez.authz.bff;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import com.logicwarez.authz.session.AuthorizationResolver;
import com.logicwarez.authz.session.SessionContext;
import com.sun.net.httpserver.HttpServer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterAll;
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
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Token relay (authz.bff.token-relay) con le sessioni su un Redis vero: il client autorizzato del login resta nella
 * sessione, l'access token scaduto si rinnova con il refresh token su un token endpoint finto, il rinnovo fallito da'
 * un risultato vuoto. Senza Docker il test viene saltato.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = BffTokenRelayTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.session.data.redis.namespace=authzrelay", "authz.bff.token-relay.enabled=true"})
@TestPropertySource(locations = "classpath:bff-test.properties")
class BffTokenRelayTest {

    @Container
    @ServiceConnection(name = "redis")
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7.4").withExposedPorts(6379);

    /** Token endpoint finto dello IAM: rinnova rt-valido, rifiuta rt-revocato, fallisce una volta con rt-instabile. */
    static final HttpServer IAM;
    static final AtomicInteger REFRESHES = new AtomicInteger();
    static final AtomicInteger FLAKY = new AtomicInteger();

    static {
        try {
            IAM = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        IAM.createContext("/token", exchange -> {
            Map<String, String> form = new LinkedHashMap<>();
            for (String pair : new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).split("&")) {
                String[] kv = pair.split("=", 2);
                form.put(kv[0], kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
            }
            String refresh = form.get("refresh_token");
            int status;
            String body;
            if (!"refresh_token".equals(form.get("grant_type"))) {
                status = 400;
                body = "{\"error\":\"unsupported_grant_type\"}";
            } else if ("rt-revocato".equals(refresh)) {
                status = 400;
                body = "{\"error\":\"invalid_grant\",\"error_description\":\"Token is not active\"}";
            } else if ("rt-instabile".equals(refresh) && FLAKY.getAndIncrement() == 0) {
                status = 503;
                body = "{\"error\":\"temporarily_unavailable\"}";
            } else {
                status = 200;
                body = "{\"access_token\":\"at-rinnovato-" + REFRESHES.incrementAndGet()
                        + "\",\"token_type\":\"Bearer\",\"expires_in\":300,\"refresh_token\":\"" + refresh + "\"}";
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        IAM.start();
    }

    @DynamicPropertySource
    static void iam(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.client.provider.iam.token-uri",
                () -> "http://127.0.0.1:" + IAM.getAddress().getPort() + "/token");
    }

    @AfterAll
    static void stopIam() {
        IAM.stop(0);
    }

    @Autowired
    Environment environment;

    private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    private String base;

    @BeforeEach
    void setUp() {
        base = "http://localhost:" + environment.getProperty("local.server.port");
    }

    @Autowired
    SecurityFilterChain chain;

    @Autowired
    SessionAccessTokens tokens;

    @Test
    void ilLoginOidcSalvaIlClientNellaSessione() {
        var login = chain.getFilters().stream()
                .filter(f -> f instanceof org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter)
                .findFirst().orElseThrow();
        assertThat(org.springframework.test.util.ReflectionTestUtils.getField(login, "authorizedClientRepository"))
                .isSameAs(tokens.repository());
    }

    @Test
    void tokenValidoInoltratoSenzaRinnovo() throws Exception {
        Browser browser = signIn("valido", "at-originale", Instant.now().plusSeconds(300), "rt-valido");
        int before = REFRESHES.get();
        assertThat(browser.send("GET", "/api/relay").body()).isEqualTo("at-originale");
        assertThat(browser.send("GET", "/api/relay").body()).isEqualTo("at-originale");
        assertThat(REFRESHES.get()).isEqualTo(before);
    }

    @Test
    void tokenScadutoRinnovatoESalvatoNellaSessione() throws Exception {
        Browser browser = signIn("scaduto", "at-vecchio", Instant.now().minusSeconds(10), "rt-valido");
        HttpResponse<String> first = browser.send("GET", "/api/relay");
        assertThat(first.statusCode()).isEqualTo(200);
        assertThat(first.body()).startsWith("at-rinnovato-");
        assertThat(browser.send("GET", "/api/relay").body()).as("riletto da Redis, senza un altro rinnovo")
                .isEqualTo(first.body());

        Browser expiring = signIn("inscadenza", "at-quasi", Instant.now().plusSeconds(30), "rt-valido");
        assertThat(expiring.send("GET", "/api/relay").body()).as("entro clock-skew").startsWith("at-rinnovato-");
    }

    @Test
    void refreshTokenRevocato401EClientTolto() throws Exception {
        Browser browser = signIn("revocato", "at-vecchio", Instant.now().minusSeconds(10), "rt-revocato");
        assertThat(browser.send("GET", "/api/relay").statusCode()).isEqualTo(401);
        assertThat(browser.send("GET", "/api/relay").body()).as("client tolto dalla sessione").isEqualTo("none");
        assertThat(browser.send("GET", "/bff/user").statusCode()).as("la sessione resta").isEqualTo(200);
    }

    @Test
    void iamNonRaggiungibileIlClientResta() throws Exception {
        Browser browser = signIn("instabile", "at-vecchio", Instant.now().minusSeconds(10), "rt-instabile");
        assertThat(browser.send("GET", "/api/relay").statusCode()).isEqualTo(401);
        assertThat(browser.send("GET", "/api/relay").body()).as("secondo tentativo").startsWith("at-rinnovato-");
    }

    @Test
    void conIlLogoutIlTokenSparisce() throws Exception {
        Browser browser = signIn("logout", "at-originale", Instant.now().plusSeconds(300), "rt-valido");
        assertThat(browser.send("GET", "/api/relay").statusCode()).isEqualTo(200);
        String session = browser.cookies.get("SESSION");
        assertThat(browser.send("POST", "/logout", "X-XSRF-TOKEN", browser.cookies.get("XSRF-TOKEN")).statusCode())
                .isEqualTo(200);
        Browser stale = new Browser();
        stale.cookies.put("SESSION", session);
        assertThat(stale.send("GET", "/api/relay").statusCode()).isEqualTo(401);
        assertThat(stale.send("GET", "/test/relay-anonymous").body()).as("senza sessione").isEqualTo("empty");
    }

    private Browser signIn(String user, String accessToken, Instant expiresAt, String refreshToken) throws Exception {
        Browser browser = new Browser();
        HttpResponse<String> r = browser.send("GET", "/test/signin?user=" + user + "-" + System.nanoTime()
                + "&access=" + accessToken + "&expires=" + expiresAt.getEpochSecond() + "&refresh=" + refreshToken);
        assertThat(r.statusCode()).as(r.body()).isEqualTo(302);
        browser.send("GET", "/bff/user");
        return browser;
    }

    private class Browser {

        private final Map<String, String> cookies = new LinkedHashMap<>();

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
    @Import({TestApp.SignIn.class, TestApp.Relay.class})
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

        /** Come il filtro di inoltro di un'applicazione: il token o 401. */
        @RestController
        static class Relay {

            static final String CLIENTS_ATTRIBUTE = org.springframework.security.oauth2.client.web
                    .HttpSessionOAuth2AuthorizedClientRepository.class.getName() + ".AUTHORIZED_CLIENTS";

            private final SessionAccessTokens tokens;

            Relay(SessionAccessTokens tokens) {
                this.tokens = tokens;
            }

            @GetMapping("/api/relay")
            ResponseEntity<String> relay(HttpServletRequest request, HttpServletResponse response) {
                // "none": nessun client autorizzato nella sessione (attributo di HttpSessionOAuth2AuthorizedClientRepository)
                var session = request.getSession(false);
                if (session == null || !(session.getAttribute(CLIENTS_ATTRIBUTE) instanceof Map<?, ?> clients)
                        || clients.isEmpty()) {
                    return ResponseEntity.ok("none");
                }
                return tokens.forRequest(request, response).map(ResponseEntity::ok)
                        .orElseGet(() -> ResponseEntity.status(401).build());
            }

            @GetMapping("/test/relay-anonymous")
            String anonymous(HttpServletRequest request, HttpServletResponse response) {
                return tokens.forRequest(request, response).isEmpty() ? "empty" : "token";
            }
        }

        @RestController
        static class SignIn {

            private final LoginSupport.LoginSuccessHandler handler;
            private final SessionAccessTokens tokens;
            private final ClientRegistrationRepository registrations;

            SignIn(LoginSupport.LoginSuccessHandler handler, SessionAccessTokens tokens,
                   ClientRegistrationRepository registrations) {
                this.handler = handler;
                this.tokens = tokens;
                this.registrations = registrations;
            }

            /** Il ritorno dallo IAM: client autorizzato salvato come fa OAuth2LoginAuthenticationFilter, poi l'esito. */
            @GetMapping("/test/signin")
            void signIn(@RequestParam String user, @RequestParam String access, @RequestParam long expires,
                        @RequestParam String refresh, HttpServletRequest request, HttpServletResponse response)
                    throws IOException {
                Instant now = Instant.now();
                OidcIdToken idToken = new OidcIdToken("id-token", now, now.plusSeconds(300),
                        Map.of("sub", "sub-" + user, "preferred_username", user, "name", user));
                OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                        new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, idToken, "sub"),
                        AuthorityUtils.NO_AUTHORITIES, "iam");
                Instant expiresAt = Instant.ofEpochSecond(expires);
                OAuth2AuthorizedClient client = new OAuth2AuthorizedClient(registrations.findByRegistrationId("iam"),
                        authentication.getName(), new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, access,
                        expiresAt.minusSeconds(600), expiresAt), new OAuth2RefreshToken(refresh, now));
                request.getSession();
                tokens.repository().saveAuthorizedClient(client, authentication, request, response);
                handler.onAuthenticationSuccess(request, response, authentication);
            }
        }
    }
}
