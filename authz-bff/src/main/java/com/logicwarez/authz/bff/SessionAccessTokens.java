package com.logicwarez.authz.bff;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;

import com.logicwarez.authz.session.SessionContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * Token relay ({@code authz.bff.token-relay.enabled}): l'access token dello IAM dell'utente della sessione, per
 * inoltrare una richiesta a un servizio separato che verifica il token ({@code Authorization: Bearer ...}).
 * <p>
 * Con il relay attivo il login lascia nella sessione (Spring Session, quindi Redis) il client autorizzato della
 * registrazione OIDC, con access e refresh token; finisce con la sessione (logout, revoca, back-channel logout).
 * Un access token scaduto (o che scade entro {@code clock-skew}) viene rinnovato con il refresh token e salvato di
 * nuovo nella sessione. Se il rinnovo fallisce il risultato e' vuoto e l'applicazione risponde {@code 401}: con il
 * refresh token scaduto o revocato il client viene tolto (serve un nuovo login), con lo IAM non raggiungibile resta.
 * <pre>
 * tokens.forRequest(request, response).ifPresentOrElse(
 *         token -> forward.header("Authorization", "Bearer " + token),
 *         () -> response.setStatus(401));
 * </pre>
 */
public class SessionAccessTokens {

    private static final Logger log = LoggerFactory.getLogger(SessionAccessTokens.class);

    private final String registrationId;
    private final OAuth2AuthorizedClientRepository repository;
    private final DefaultOAuth2AuthorizedClientManager manager;

    public SessionAccessTokens(ClientRegistrationRepository registrations, BffProperties properties, Clock clock) {
        this.registrationId = properties.oidc().registrationId();
        this.repository = new HttpSessionOAuth2AuthorizedClientRepository();
        this.manager = new DefaultOAuth2AuthorizedClientManager(registrations, repository);
        Duration skew = properties.tokenRelay().clockSkew();
        // solo rinnovo: senza un client nella sessione non si avvia un nuovo login da qui
        this.manager.setAuthorizedClientProvider(OAuth2AuthorizedClientProviderBuilder.builder()
                .refreshToken(refresh -> refresh.clockSkew(skew).clock(clock))
                .build());
    }

    /** Dove il login salva il client autorizzato: la sessione HTTP. */
    OAuth2AuthorizedClientRepository repository() {
        return repository;
    }

    /**
     * Access token valido dell'utente della sessione, rinnovato se scaduto. Vuoto senza una sessione del browser,
     * senza token (sessione aperta prima del relay) o se il rinnovo fallisce.
     */
    public Optional<String> forRequest(HttpServletRequest request, HttpServletResponse response) {
        Optional<SessionContext> session = SessionContext.from(request);
        if (session.isEmpty()) {
            return Optional.empty();
        }
        try {
            OAuth2AuthorizedClient client = manager.authorize(OAuth2AuthorizeRequest
                    .withClientRegistrationId(registrationId)
                    .principal(session.get().username())
                    .attribute(HttpServletRequest.class.getName(), request)
                    .attribute(HttpServletResponse.class.getName(), response)
                    .build());
            return client == null ? Optional.empty() : Optional.of(client.getAccessToken().getTokenValue());
        } catch (RuntimeException e) {
            // invalid_grant (refresh token scaduto o revocato): il manager ha gia' tolto il client dalla sessione.
            // Altri errori (IAM non raggiungibile): il client resta, un tentativo successivo puo' riuscire.
            log.info("Access token non rinnovato per {}: {}", session.get().username(), e.getMessage());
            return Optional.empty();
        }
    }
}
