package com.logicwarez.authz.bff;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

import com.logicwarez.authz.session.SessionAuthentication;
import com.logicwarez.authz.session.SessionContext;
import com.logicwarez.authz.session.TokenAuthentication;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Regole sulle richieste delle sessioni del browser: login recente prima delle azioni sensibili
 * ({@code authz.bff.recent-login}) e limite di frequenza per utente ({@code authz.bff.session-rate-limit}).
 * Le richieste con un token ({@link TokenAuthentication}) non passano di qui.
 */
final class SessionGuards {

    /** Attributi di sessione: momento dell'autenticazione sullo IAM, max_age chiesto da /bff/login. */
    static final String AUTH_TIME = "authz.bff.auth_time";
    static final String MAX_AGE = "authz.bff.max_age";

    /** Tipo del Problem quando serve un login piu' recente. */
    static final String RECENT_LOGIN_REQUIRED = "urn:problem:authz:recent-login-required";

    private SessionGuards() {
    }

    /** Sessione del browser autenticata, null per una richiesta anonima o con un token. */
    static SessionContext browserSession() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication instanceof SessionAuthentication && !(authentication instanceof TokenAuthentication)
                && authentication.getPrincipal() instanceof SessionContext session ? session : null;
    }

    /**
     * Percorsi delle proprieta': {@code /api/admin/**} (tutti i metodi) o {@code POST /api/me/tokens} (solo quel
     * metodo).
     */
    static List<RequestMatcher> matchers(List<String> entries) {
        return entries.stream().map(String::strip).filter(e -> !e.isEmpty()).map(entry -> {
            int space = entry.indexOf(' ');
            PathPatternRequestMatcher.Builder builder = PathPatternRequestMatcher.withDefaults();
            return space < 0 ? (RequestMatcher) builder.matcher(entry)
                    : builder.matcher(HttpMethod.valueOf(entry.substring(0, space).toUpperCase(Locale.ROOT)),
                            entry.substring(space + 1).strip());
        }).toList();
    }

    /**
     * Sui percorsi indicati, una sessione autenticata sullo IAM da piu' di {@code max-age} riceve {@code 401} con
     * il Problem {@value #RECENT_LOGIN_REQUIRED}: la pagina rimanda a {@code /bff/login?max_age=...} e lo IAM chiede di
     * nuovo le credenziali. Una sessione senza il momento dell'autenticazione (aperta prima della 2.4.0) conta come
     * vecchia.
     */
    static final class RecentLoginFilter extends OncePerRequestFilter {

        private final List<RequestMatcher> paths;
        private final Duration maxAge;
        private final Clock clock;

        RecentLoginFilter(BffProperties.RecentLogin properties, Clock clock) {
            this.paths = matchers(properties.paths());
            this.maxAge = properties.maxAge();
            this.clock = clock;
        }

        @Override
        protected boolean shouldNotFilter(HttpServletRequest request) {
            return paths.stream().noneMatch(p -> p.matches(request));
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            HttpSession session = request.getSession(false);
            if (browserSession() != null && session != null) {
                Instant authTime = session.getAttribute(AUTH_TIME) instanceof Instant t ? t : null;
                if (authTime == null || authTime.plus(maxAge).isBefore(clock.instant())) {
                    BffConfigurer.problem(response, HttpStatus.UNAUTHORIZED, RECENT_LOGIN_REQUIRED,
                            "Recent login required", "\"maxAge\":" + maxAge.toSeconds());
                    return;
                }
            }
            chain.doFilter(request, response);
        }
    }

    /** Limite per utente sulle richieste delle sessioni del browser, contatore su Redis, fail-open. */
    static final class SessionRateLimitFilter extends OncePerRequestFilter {

        private final List<RequestMatcher> paths;
        private final RateCounter counter;
        private final Duration window;

        SessionRateLimitFilter(BffProperties.SessionRateLimit properties, StringRedisTemplate redis) {
            this.paths = matchers(properties.paths());
            this.counter = new RateCounter(redis, properties.redisKeyPrefix(), properties.maxRequests(),
                    properties.window(), "sessioni");
            this.window = properties.window();
        }

        @Override
        protected boolean shouldNotFilter(HttpServletRequest request) {
            return paths.stream().noneMatch(p -> p.matches(request));
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            SessionContext session = browserSession();
            if (session != null && counter.overLimit(session.username())) {
                response.setHeader("Retry-After", String.valueOf(Math.max(1, window.toSeconds())));
                BffConfigurer.problem(response, HttpStatus.TOO_MANY_REQUESTS, "Too many requests");
                return;
            }
            chain.doFilter(request, response);
        }
    }

    /** Contatore a finestra fissa su Redis condiviso tra le istanze; senza Redis o con Redis giu' non limita. */
    static final class RateCounter {

        private static final Logger log = LoggerFactory.getLogger(RateCounter.class);

        private final StringRedisTemplate redis;
        private final String prefix;
        private final int max;
        private final Duration window;
        private final String label;

        RateCounter(StringRedisTemplate redis, String prefix, int max, Duration window, String label) {
            this.redis = redis;
            this.prefix = prefix;
            this.max = max;
            this.window = window;
            this.label = label;
        }

        boolean overLimit(String id) {
            if (redis == null) {
                return false;
            }
            String key = prefix + id;
            try {
                Long count = redis.opsForValue().increment(key);
                if (count != null && count == 1) {
                    redis.expire(key, window);
                }
                return count != null && count > max;
            } catch (DataAccessException e) {
                log.warn("Rate limiting delle {} non disponibile: {}", label, e.toString());
                return false;
            }
        }
    }

    /**
     * Richiesta di autorizzazione allo IAM con il {@code max_age} chiesto da {@code /bff/login}: lo IAM chiede di
     * nuovo le credenziali se la sua sessione e' piu' vecchia (con 0, sempre).
     */
    static final class MaxAgeAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

        private final DefaultOAuth2AuthorizationRequestResolver delegate;

        MaxAgeAuthorizationRequestResolver(ClientRegistrationRepository registrations) {
            this.delegate = new DefaultOAuth2AuthorizationRequestResolver(registrations,
                    DefaultOAuth2AuthorizationRequestResolver.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        }

        @Override
        public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
            return withMaxAge(delegate.resolve(request), request);
        }

        @Override
        public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId) {
            return withMaxAge(delegate.resolve(request, registrationId), request);
        }

        private static OAuth2AuthorizationRequest withMaxAge(OAuth2AuthorizationRequest authorization,
                                                             HttpServletRequest request) {
            HttpSession session = request.getSession(false);
            if (authorization == null || session == null || !(session.getAttribute(MAX_AGE) instanceof Long maxAge)) {
                return authorization;
            }
            return OAuth2AuthorizationRequest.from(authorization)
                    .additionalParameters(p -> p.put("max_age", maxAge))
                    .authorizationRequestUri(UriComponentsBuilder.fromUriString(authorization.getAuthorizationRequestUri())
                            .queryParam("max_age", maxAge).build(true).toUriString())
                    .build();
        }
    }
}
