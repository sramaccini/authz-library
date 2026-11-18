package com.logicwarez.authz.bff;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.function.Supplier;

import com.logicwarez.authz.session.AuthorizationResolver;
import com.logicwarez.authz.session.PersonalAccessTokenVerifier;
import com.logicwarez.authz.session.SessionContext;
import com.logicwarez.authz.session.TenantSelectionRequiredException;
import com.logicwarez.authz.session.TokenAuthentication;
import com.logicwarez.authz.session.UserNotAuthorizedException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Accesso con {@code Authorization: Bearer} sui percorsi di {@code authz.bff.bearer.paths}, per chi non tiene una
 * sessione (strumenti, integrazioni, service account). Il token dice solo chi e' l'utente: ruoli e permessi sono
 * risolti come per una sessione ({@link AuthorizationResolver#resolveForToken}), sul tenant dell'header
 * {@code X-Tenant} o sull'ultimo usato, e messi in un {@link TokenAuthentication} che non viene mai salvato.
 * <ul>
 *   <li>Token: access token dello IAM (JWT verificato con l'emittente, client in {@code allowed-clients}) o token di
 *       accesso personale ({@code pat_...}, con un {@link PersonalAccessTokenVerifier}).</li>
 *   <li>Niente CSRF ne' controllo Origin: il token non viaggia da solo come un cookie. Per lo stesso motivo una
 *       richiesta con sia il cookie di sessione sia il token e' rifiutata (400).</li>
 *   <li>Limite di frequenza per utente su Redis (fail-open).</li>
 * </ul>
 */
final class BearerTokenFilter extends OncePerRequestFilter {

    /** Attributo della richiesta autenticata con un token: CSRF e controllo Origin non si applicano. */
    static final String ATTRIBUTE = BearerTokenFilter.class.getName();

    private static final Logger log = LoggerFactory.getLogger(BearerTokenFilter.class);
    private static final String SCHEME = "Bearer ";

    private final List<RequestMatcher> paths;
    private final BffProperties.Bearer properties;
    private final BffProperties.Oidc oidc;
    private final Supplier<JwtDecoder> decoder;
    private final ObjectProvider<PersonalAccessTokenVerifier> personalTokens;
    private final AuthorizationResolver resolver;
    private final SessionGuards.RateCounter rateCounter;
    private final Clock clock;
    private final SecurityContextHolderStrategy contextHolder = SecurityContextHolder.getContextHolderStrategy();
    private final RequestAttributeSecurityContextRepository repository = new RequestAttributeSecurityContextRepository();

    BearerTokenFilter(BffProperties properties, Supplier<JwtDecoder> decoder,
                      ObjectProvider<PersonalAccessTokenVerifier> personalTokens, AuthorizationResolver resolver,
                      StringRedisTemplate redis, Clock clock) {
        this.paths = properties.bearer().paths().stream()
                .map(p -> (RequestMatcher) PathPatternRequestMatcher.withDefaults().matcher(p)).toList();
        this.properties = properties.bearer();
        this.oidc = properties.oidc();
        this.decoder = decoder;
        this.personalTokens = personalTokens;
        this.resolver = resolver;
        BffProperties.RateLimit limit = properties.bearer().rateLimit();
        this.rateCounter = limit.enabled() ? new SessionGuards.RateCounter(redis, limit.redisKeyPrefix(),
                limit.maxRequests(), limit.window(), "richieste con token") : null;
        this.clock = clock;
    }

    static boolean isBearer(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        return authorization != null && authorization.regionMatches(true, 0, SCHEME, 0, SCHEME.length());
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !isBearer(request) || paths.stream().noneMatch(p -> p.matches(request));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getRequestedSessionId() != null) {
            BffConfigurer.problem(response, HttpStatus.BAD_REQUEST,
                    "Send either a session cookie or a bearer token, not both");
            return;
        }
        Identity identity = identify(request.getHeader("Authorization").substring(SCHEME.length()).strip());
        if (identity == null) {
            response.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            BffConfigurer.problem(response, HttpStatus.UNAUTHORIZED, "Invalid or expired token");
            return;
        }
        if (overLimit(identity.username())) {
            response.setHeader("Retry-After",
                    String.valueOf(Math.max(1, properties.rateLimit().window().toSeconds())));
            BffConfigurer.problem(response, HttpStatus.TOO_MANY_REQUESTS, "Too many requests");
            return;
        }
        String tenant = request.getHeader(properties.tenantHeader());
        AuthorizationResolver.Resolved resolved;
        try {
            resolved = resolver.resolveForToken(identity.username(), tenant == null || tenant.isBlank() ? null : tenant);
        } catch (UserNotAuthorizedException e) {
            BffConfigurer.problem(response, HttpStatus.FORBIDDEN, tenant == null || tenant.isBlank()
                    ? "User not authorized" : "Tenant not available to the user");
            return;
        } catch (TenantSelectionRequiredException e) {
            BffConfigurer.problem(response, HttpStatus.BAD_REQUEST,
                    "Tenant required: send the " + properties.tenantHeader() + " header");
            return;
        }
        SessionContext session = new SessionContext(resolved.username(),
                identity.name() == null ? resolved.username() : identity.name(), resolved.email(),
                resolved.tenantId(), resolved.tenants(), resolved.roles(), resolved.permissions(),
                clock.instant(), identity.expiresAt());
        SecurityContext context = contextHolder.createEmptyContext();
        context.setAuthentication(new TokenAuthentication(session, identity.client()));
        contextHolder.setContext(context);
        // Per gli async dispatch (stream di eventi) e il dispatch verso /error, dove questo filtro non gira
        repository.saveContext(context, request, response);
        request.setAttribute(ATTRIBUTE, Boolean.TRUE);
        chain.doFilter(request, response);
    }

    private Identity identify(String token) {
        if (token.startsWith(PersonalAccessTokenVerifier.PREFIX)) {
            PersonalAccessTokenVerifier verifier = personalTokens.getIfAvailable();
            return verifier == null ? null : verifier.verify(token)
                    .map(o -> new Identity(o.username(), null, TokenAuthentication.PERSONAL_ACCESS_TOKEN, o.expiresAt()))
                    .orElse(null);
        }
        JwtDecoder jwtDecoder = decoder.get();
        if (jwtDecoder == null) {
            return null;
        }
        try {
            Jwt jwt = jwtDecoder.decode(token);
            String username = jwt.getClaimAsString(oidc.usernameClaim());
            return username == null || username.isBlank() ? null
                    : new Identity(username, jwt.getClaimAsString(oidc.nameClaim()), jwt.getClaimAsString("azp"),
                            jwt.getExpiresAt());
        } catch (JwtException e) {
            log.debug("Token rifiutato: {}", e.getMessage());
            return null;
        }
    }

    private boolean overLimit(String username) {
        return rateCounter != null && rateCounter.overLimit(username);
    }

    private record Identity(String username, String name, String client, Instant expiresAt) {
    }
}
