package com.logicwarez.authz.bff;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.core.env.Environment;
import org.springframework.test.context.TestPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Limite di richieste per utente dell'accesso con token, contato su un Redis vero: oltre il massimo nella finestra
 * risponde 429 con Retry-After, per lo stesso utente qualunque sia il token. Senza Docker il test viene saltato.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = BffBearerTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"authz.bff.bearer.enabled=true", "authz.bff.bearer.rate-limit.max-requests=3",
                "authz.bff.bearer.rate-limit.window=1m"})
@TestPropertySource(locations = "classpath:bff-test.properties")
class BffBearerRateLimitTest {

    @Container
    @ServiceConnection(name = "redis")
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7.4").withExposedPorts(6379);

    @Autowired
    Environment environment;

    @Test
    void oltreIlLimiteRisponde429() throws Exception {
        HttpClient http = HttpClient.newHttpClient();
        URI uri = URI.create("http://localhost:" + environment.getProperty("local.server.port") + "/api/whoami");
        for (int i = 0; i < 3; i++) {
            String token = i % 2 == 0 ? TestTokens.token("anna.bianchi") : BffBearerTest.PERSONAL_TOKEN;
            assertThat(http.send(HttpRequest.newBuilder(uri).header("Authorization", "Bearer " + token).build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(200);
        }
        HttpResponse<String> limited = http.send(HttpRequest.newBuilder(uri)
                .header("Authorization", "Bearer " + TestTokens.token("anna.bianchi")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(limited.statusCode()).isEqualTo(429);
        assertThat(limited.headers().firstValue("Retry-After")).hasValue("60");
    }
}
