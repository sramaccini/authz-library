package com.logicwarez.authz.bff;

import java.net.URI;
import java.time.Duration;
import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Configurazione del BFF incorporato. Cookie, timeout di inattivita' e Redis sono le proprieta' standard
 * di Spring Boot e Spring Session (server.servlet.session.*, spring.session.*, spring.data.redis.*).
 */
@Validated
@ConfigurationProperties("authz.bff")
public record BffProperties(@Valid @DefaultValue Oidc oidc,
                            @Valid @DefaultValue Session session,
                            @Valid @NotNull Frontend frontend,
                            @Valid @DefaultValue LoginRateLimit loginRateLimit,
                            @Valid @DefaultValue Bearer bearer) {

    /** @param nameClaim claim con il nome completo da mostrare (campo name di /bff/user) */
    public record Oidc(@DefaultValue("iam") @NotBlank String registrationId,
                       @DefaultValue("preferred_username") @NotBlank String usernameClaim,
                       @DefaultValue("name") @NotBlank String nameClaim) {
    }

    /**
     * @param loginSuccessUrl home delle applicazioni: destinazione del login senza pagina di ritorno
     * @param allowedOrigins  origini delle applicazioni: pagine di ritorno del login e header Origin ammessi
     *                        (l'origine pubblica del BFF e' sempre ammessa)
     */

    /** @param absoluteTimeout durata massima di una sessione anche se l'utente resta attivo */
    public record Session(@DefaultValue("10h") @NotNull Duration absoluteTimeout) {
    }

    public record Frontend(@NotNull URI loginSuccessUrl,
                           @NotNull URI loginFailureUrl,
                           @NotNull URI postLogoutUrl,
                           @DefaultValue List<String> allowedOrigins) {
    }

    /** Limite per IP sugli ingressi del login OIDC, con contatore condiviso su Redis. */
    public record LoginRateLimit(@DefaultValue("true") boolean enabled,
                                 @DefaultValue("20") @Positive int maxRequests,
                                 @DefaultValue("1m") @NotNull Duration window,
                                 @DefaultValue("authz:ratelimit:login:") @NotBlank String redisKeyPrefix) {
    }

    /**
     * Accesso con un token ({@code Authorization: Bearer}) per strumenti e integrazioni che non tengono una sessione:
     * un access token dello IAM (utente o service account) o un token di accesso personale ({@code pat_...}).
     *
     * @param paths          percorsi su cui il token e' accettato (altrove l'header e' ignorato)
     * @param issuerUri      emittente dei token; vuoto: quello del provider OIDC del login
     * @param allowedClients client ({@code azp}) i cui token sono accettati; vuoto: tutti i client dell'emittente
     * @param tenantHeader   header con il tenant della richiesta; senza, l'ultimo tenant usato dall'utente
     */
    public record Bearer(@DefaultValue("false") boolean enabled,
                         @DefaultValue("/api/**") List<String> paths,
                         URI issuerUri,
                         @DefaultValue List<String> allowedClients,
                         @DefaultValue("X-Tenant") @NotBlank String tenantHeader,
                         @Valid @DefaultValue RateLimit rateLimit) {
    }

    /** Limite per utente (o service account) sulle richieste con un token, con contatore condiviso su Redis. */
    public record RateLimit(@DefaultValue("true") boolean enabled,
                            @DefaultValue("600") @Positive int maxRequests,
                            @DefaultValue("1m") @NotNull Duration window,
                            @DefaultValue("authz:ratelimit:bearer:") @NotBlank String redisKeyPrefix) {
    }
}
