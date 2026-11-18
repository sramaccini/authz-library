package com.logicwarez.authz.bff;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.logicwarez.authz.session.AuthorizationResolver;
import com.logicwarez.authz.session.SessionContext;
import com.logicwarez.authz.session.TenantSelectionRequiredException;
import com.logicwarez.authz.session.UserNotAuthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.web.util.UriComponentsBuilder;

/** Componenti del login OIDC e del logout: redirect, gestori di esito, URL di logout sullo IAM, controllo Origin. */
public final class LoginSupport {

    /** Attributi di sessione riservati al BFF. */
    static final String TENANT_HINT = "authz.bff.tenant";
    static final String RETURN_TO = "authz.bff.return";
    static final String ID_TOKEN = "authz.bff.id_token";

    private LoginSupport() {
    }

    /** Codici restituiti al frontend come ?error= sulla pagina di errore del login. */
    public enum LoginErrorCode {
        ACCESS_DENIED("access_denied"),
        TENANT_SELECTION_REQUIRED("tenant_selection_required"),
        AUTH_SERVICE_UNAVAILABLE("auth_service_unavailable"),
        LOGIN_FAILED("login_failed");

        private final String code;

        LoginErrorCode(String code) {
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    /**
     * Origini delle applicazioni servite dal BFF: quelle configurate (authz.bff.frontend.allowed-origins) piu'
     * l'origine pubblica del BFF stesso, per le pagine servite sullo stesso indirizzo (per esempio dall'immagine
     * runtime di Quadrava). Dietro un proxy l'origine pubblica richiede server.forward-headers-strategy=framework.
     */
    public static class Origins {

        private final Set<String> allowed;

        public Origins(BffProperties properties) {
            this.allowed = properties.frontend().allowedOrigins().stream()
                    .map(o -> o.replaceAll("/+$", "").toLowerCase(Locale.ROOT))
                    .collect(Collectors.toUnmodifiableSet());
        }

        public boolean isApplication(String origin, HttpServletRequest request) {
            if (origin == null) {
                return false;
            }
            String normalized = origin.toLowerCase(Locale.ROOT);
            return allowed.contains(normalized) || normalized.equals(own(request));
        }

        /** L'indirizzo, se e' un URL http(s) assoluto senza credenziali in una delle origini delle applicazioni. */
        public Optional<String> applicationUrl(String url, HttpServletRequest request) {
            try {
                URI uri = new URI(url);
                String scheme = uri.getScheme() == null ? null : uri.getScheme().toLowerCase(Locale.ROOT);
                if (!("http".equals(scheme) || "https".equals(scheme)) || uri.getHost() == null
                        || uri.getRawUserInfo() != null) {
                    return Optional.empty();
                }
                return isApplication(origin(scheme, uri.getHost(), uri.getPort()), request)
                        ? Optional.of(uri.toString()) : Optional.empty();
            } catch (URISyntaxException e) {
                return Optional.empty();
            }
        }

        private static String own(HttpServletRequest request) {
            return origin(request.getScheme(), request.getServerName(), request.getServerPort());
        }

        private static String origin(String scheme, String host, int port) {
            boolean defaultPort = port == -1 || ("http".equalsIgnoreCase(scheme) && port == 80)
                    || ("https".equalsIgnoreCase(scheme) && port == 443);
            return (scheme + "://" + host + (defaultPort ? "" : ":" + port)).toLowerCase(Locale.ROOT);
        }
    }

    /** Redirect verso la pagina di ritorno gia' verificata o verso URL del frontend fissi (nessun open redirect). */
    public static class LoginRedirects {

        private final BffProperties.Frontend frontend;

        public LoginRedirects(BffProperties properties) {
            this.frontend = properties.frontend();
        }

        void toSuccess(HttpServletResponse response, String returnTo) throws IOException {
            response.sendRedirect(returnTo != null ? returnTo : frontend.loginSuccessUrl().toString());
        }

        void toFailure(HttpServletResponse response, LoginErrorCode error) throws IOException {
            response.sendRedirect(UriComponentsBuilder.fromUri(frontend.loginFailureUrl())
                    .queryParam("error", error.code()).build(true).toUriString());
        }
    }

    /**
     * Dopo il login OIDC: risolve ruoli e permessi in-process, salva il {@link SessionContext} nella sessione
     * (gia' rigenerata da Spring Security contro la session fixation), indicizza la sessione per username
     * (revoca), conserva solo l'ID token per il logout sullo IAM e torna alla pagina indicata da /bff/login.
     * Access e refresh token vengono eliminati, salvo con authz.bff.token-relay (restano nella sessione).
     */
    public static class LoginSuccessHandler implements AuthenticationSuccessHandler {

        private static final Logger log = LoggerFactory.getLogger(LoginSuccessHandler.class);

        private final AuthorizationResolver resolver;
        private final ObjectProvider<OAuth2AuthorizedClientRepository> authorizedClients;
        private final LoginRedirects redirects;
        private final BffProperties properties;
        private final Clock clock;
        private final BackChannelLogout.SessionIndex sessionIndex;

        public LoginSuccessHandler(AuthorizationResolver resolver,
                                   ObjectProvider<OAuth2AuthorizedClientRepository> authorizedClients,
                                   LoginRedirects redirects, BffProperties properties, Clock clock) {
            this(resolver, authorizedClients, redirects, properties, clock, null);
        }

        /** @param sessionIndex indice per il back-channel logout; null se non attivo */
        public LoginSuccessHandler(AuthorizationResolver resolver,
                                   ObjectProvider<OAuth2AuthorizedClientRepository> authorizedClients,
                                   LoginRedirects redirects, BffProperties properties, Clock clock,
                                   BackChannelLogout.SessionIndex sessionIndex) {
            this.resolver = resolver;
            this.authorizedClients = authorizedClients;
            this.redirects = redirects;
            this.properties = properties;
            this.clock = clock;
            this.sessionIndex = sessionIndex;
        }

        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                            Authentication authentication) throws IOException {
            HttpSession session = request.getSession();
            Object tenant = session.getAttribute(TENANT_HINT);
            Object returnTo = session.getAttribute(RETURN_TO);
            session.removeAttribute(TENANT_HINT);
            session.removeAttribute(RETURN_TO);
            session.removeAttribute(SessionGuards.MAX_AGE);
            if (!(authentication instanceof OAuth2AuthenticationToken oauth)) {
                fail(request, response, LoginErrorCode.LOGIN_FAILED);
                return;
            }
            if (!properties.tokenRelay().enabled()) {
                removeAuthorizedClient(oauth, request, response);
            }
            String username = oauth.getPrincipal().getAttribute(properties.oidc().usernameClaim());
            if (username == null || username.isBlank()) {
                log.warn("Claim '{}' assente nel token IAM", properties.oidc().usernameClaim());
                fail(request, response, LoginErrorCode.LOGIN_FAILED);
                return;
            }
            AuthorizationResolver.Resolved resolved;
            try {
                resolved = resolver.resolve(username, tenant instanceof String t ? t : null);
            } catch (UserNotAuthorizedException e) {
                log.info("Utente {} non abilitato", username);
                fail(request, response, LoginErrorCode.ACCESS_DENIED);
                return;
            } catch (TenantSelectionRequiredException e) {
                fail(request, response, LoginErrorCode.TENANT_SELECTION_REQUIRED);
                return;
            } catch (RuntimeException e) {
                log.error("Risoluzione dei permessi fallita per {}: {}", username, e.toString());
                fail(request, response, LoginErrorCode.AUTH_SERVICE_UNAVAILABLE);
                return;
            }
            Instant now = clock.instant();
            String name = oauth.getPrincipal().getAttribute(properties.oidc().nameClaim());
            session.setAttribute(SessionContext.ATTRIBUTE, new SessionContext(resolved.username(), name,
                    resolved.email(), resolved.tenantId(), resolved.tenants(), resolved.roles(),
                    resolved.permissions(), now, now.plus(properties.session().absoluteTimeout())));
            session.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, resolved.username());
            // per l'elenco delle sessioni dell'utente: da dove e con cosa si e' collegato
            session.setAttribute(UserSessions.CLIENT_IP, request.getRemoteAddr());
            String agent = request.getHeader("User-Agent");
            if (agent != null) {
                session.setAttribute(UserSessions.USER_AGENT,
                        agent.length() > UserSessions.USER_AGENT_MAX ? agent.substring(0, UserSessions.USER_AGENT_MAX) : agent);
            }
            // momento dell'autenticazione sullo IAM (claim auth_time), per authz.bff.recent-login; senza: il login
            Instant authTime = oauth.getPrincipal() instanceof OidcUser user && user.getIdToken().getAuthenticatedAt() != null
                    ? user.getIdToken().getAuthenticatedAt() : now;
            session.setAttribute(SessionGuards.AUTH_TIME, authTime.isAfter(now) ? now : authTime);
            if (oauth.getPrincipal() instanceof OidcUser oidc) {
                session.setAttribute(ID_TOKEN, oidc.getIdToken().getTokenValue());
                String sid = oidc.getIdToken().getClaimAsString("sid");
                if (sid != null) {
                    session.setAttribute(UserSessions.OIDC_SID, sid);
                }
                session.setAttribute(UserSessions.OIDC_SUB, oidc.getSubject());
                if (sessionIndex != null) {
                    try {
                        sessionIndex.remember(sid, oidc.getSubject(), resolved.username());
                    } catch (RuntimeException e) {
                        log.warn("Indice del back-channel logout non aggiornato per {}: {}", resolved.username(), e.toString());
                    }
                }
            }
            log.info("Sessione creata per utente={} tenant={}", resolved.username(), resolved.tenantId());
            redirects.toSuccess(response, returnTo instanceof String url ? url : null);
        }

        private void removeAuthorizedClient(OAuth2AuthenticationToken oauth, HttpServletRequest request,
                                            HttpServletResponse response) {
            OAuth2AuthorizedClientRepository repository = authorizedClients.getIfAvailable();
            if (repository != null) {
                repository.removeAuthorizedClient(oauth.getAuthorizedClientRegistrationId(), oauth, request, response);
            }
        }

        private void fail(HttpServletRequest request, HttpServletResponse response, LoginErrorCode code)
                throws IOException {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            redirects.toFailure(response, code);
        }
    }

    /** Login OIDC fallito prima di arrivare all'esito (errore dello IAM, state non valido...). */
    public static class LoginFailureHandler implements AuthenticationFailureHandler {

        private final LoginRedirects redirects;

        public LoginFailureHandler(LoginRedirects redirects) {
            this.redirects = redirects;
        }

        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException exception) throws IOException {
            redirects.toFailure(response, LoginErrorCode.LOGIN_FAILED);
        }
    }

    /**
     * URL di logout sullo IAM (OIDC RP-Initiated Logout): end_session_endpoint con id_token_hint, client_id e
     * post_logout_redirect_uri. Senza endpoint pubblicato dallo IAM si torna direttamente al frontend.
     */
    public static class IamLogout {

        private final ClientRegistrationRepository registrations;
        private final String registrationId;
        private final String postLogoutUrl;

        public IamLogout(ClientRegistrationRepository registrations, BffProperties properties) {
            this.registrations = registrations;
            this.registrationId = properties.oidc().registrationId();
            this.postLogoutUrl = properties.frontend().postLogoutUrl().toString();
        }

        public String logoutUrl(String idToken) {
            ClientRegistration registration = registrations.findByRegistrationId(registrationId);
            Object endpoint = registration == null ? null
                    : registration.getProviderDetails().getConfigurationMetadata().get("end_session_endpoint");
            if (endpoint == null) {
                return postLogoutUrl;
            }
            UriComponentsBuilder url = UriComponentsBuilder.fromUriString(endpoint.toString())
                    .queryParam("client_id", registration.getClientId())
                    .queryParam("post_logout_redirect_uri", postLogoutUrl);
            if (idToken != null) {
                url.queryParam("id_token_hint", idToken);
            }
            return url.encode().build().toUriString();
        }
    }

    /**
     * Difesa in profondita' accanto al token CSRF: una richiesta non idempotente con un header Origin estraneo
     * alle applicazioni viene rifiutata. Senza Origin (client non browser) decide il solo token CSRF.
     */
    public static class OriginPolicy {

        private static final Set<String> SAFE_METHODS =
                Set.of(HttpMethod.GET.name(), HttpMethod.HEAD.name(), HttpMethod.OPTIONS.name());

        private final Origins origins;

        public OriginPolicy(Origins origins) {
            this.origins = origins;
        }

        public boolean isAllowed(HttpServletRequest request) {
            if (SAFE_METHODS.contains(request.getMethod())) {
                return true;
            }
            String origin = request.getHeader("Origin");
            return origin == null || origins.isApplication(origin, request);
        }
    }
}
