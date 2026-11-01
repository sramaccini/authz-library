package com.logicwarez.authz.bff;

import java.io.IOException;

import com.logicwarez.authz.session.SessionContext;
import com.logicwarez.authz.session.SessionContextConfigurer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * BFF incorporato nell'applicazione:
 * <pre>
 * http.with(BffConfigurer.bff(), Customizer.withDefaults())
 *     .authorizeHttpRequests(auth -> auth
 *         .requestMatchers(BffControllers.PUBLIC_PATHS).permitAll()
 *         .anyRequest().authenticated());
 * </pre>
 * Login OIDC, SessionContext in Spring Session, 401 sulle chiamate senza sessione (mai redirect), CSRF per
 * applicazioni a pagina singola (cookie XSRF-TOKEN leggibile dalla pagina, header X-XSRF-TOKEN sulle scritture),
 * controllo Origin, header X-Permissions-Version e limite di frequenza sul login: le regole di contracts/bff.yaml
 * di Quadrava.
 */
public class BffConfigurer extends AbstractHttpConfigurer<BffConfigurer, HttpSecurity> {

    public static BffConfigurer bff() {
        return new BffConfigurer();
    }

    @Override
    public void init(HttpSecurity http) {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        http.with(SessionContextConfigurer.sessionContext(), Customizer.withDefaults());
        http.oauth2Login(login -> login
                .successHandler(context.getBean(LoginSupport.LoginSuccessHandler.class))
                .failureHandler(context.getBean(LoginSupport.LoginFailureHandler.class)));
        // API per una SPA: mai redirect alla pagina di login, sempre 401
        http.exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
        // spa(): token letto dall'header X-XSRF-TOKEN; il cookie XSRF-TOKEN non e' HttpOnly perche' la pagina lo legge
        http.csrf(csrf -> csrf.spa().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
        // POST /logout e' di BffControllers (risposta JSON con l'indirizzo di logout sullo IAM)
        http.logout(logout -> logout.disable());
    }

    @Override
    public void configure(HttpSecurity http) {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        BffProperties properties = context.getBean(BffProperties.class);
        http.addFilterAfter(new OriginCheckFilter(context.getBean(LoginSupport.OriginPolicy.class)),
                SecurityContextHolderFilter.class);
        http.addFilterAfter(new CsrfCookieFilter(), CsrfFilter.class);
        http.addFilterAfter(new PermissionsVersionFilter(), CsrfFilter.class);
        if (properties.loginRateLimit().enabled()) {
            http.addFilterBefore(new LoginRateLimitFilter(context.getBeanProvider(StringRedisTemplate.class)
                    .getIfAvailable(), properties.loginRateLimit()), OAuth2AuthorizationRequestRedirectFilter.class);
        }
    }

    static void problem(HttpServletResponse response, HttpStatus status, String detail) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.getWriter().write("{\"type\":\"about:blank\",\"title\":\"" + status.getReasonPhrase()
                + "\",\"status\":" + status.value() + ",\"detail\":\"" + detail + "\"}");
    }

    static final class OriginCheckFilter extends OncePerRequestFilter {

        private final LoginSupport.OriginPolicy policy;

        OriginCheckFilter(LoginSupport.OriginPolicy policy) {
            this.policy = policy;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            if (!policy.isAllowed(request)) {
                problem(response, HttpStatus.FORBIDDEN, "Origin not allowed");
                return;
            }
            chain.doFilter(request, response);
        }
    }

    /**
     * Legge il token CSRF a ogni richiesta, cosi' il cookie XSRF-TOKEN arriva al browser gia' con la prima risposta
     * (Spring Security lo crea solo quando qualcuno lo legge).
     */
    static final class CsrfCookieFilter extends OncePerRequestFilter {

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            if (request.getAttribute(CsrfToken.class.getName()) instanceof CsrfToken token) {
                token.getToken();
            }
            chain.doFilter(request, response);
        }
    }

    /** Versione dei permessi della sessione su ogni risposta: quando cambia, la UI ricarica i permessi. */
    static final class PermissionsVersionFilter extends OncePerRequestFilter {

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.getPrincipal() instanceof SessionContext session) {
                response.setHeader(AuthzController.VERSION_HEADER, session.permissionsVersion());
            }
            chain.doFilter(request, response);
        }
    }

    /** Limite per IP sugli ingressi del login; contatore su Redis condiviso tra le istanze, fail-open. */
    static final class LoginRateLimitFilter extends OncePerRequestFilter {

        private static final Logger log = LoggerFactory.getLogger(LoginRateLimitFilter.class);

        private final StringRedisTemplate redis;
        private final BffProperties.LoginRateLimit limit;

        LoginRateLimitFilter(StringRedisTemplate redis, BffProperties.LoginRateLimit limit) {
            this.redis = redis;
            this.limit = limit;
        }

        @Override
        protected boolean shouldNotFilter(HttpServletRequest request) {
            String path = request.getRequestURI().substring(request.getContextPath().length());
            return redis == null || !(path.equals("/bff/login") || path.startsWith("/oauth2/authorization/")
                    || path.startsWith("/login/oauth2/code/"));
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String key = limit.redisKeyPrefix() + request.getRemoteAddr();
            try {
                Long count = redis.opsForValue().increment(key);
                if (count != null && count == 1) {
                    redis.expire(key, limit.window());
                }
                if (count != null && count > limit.maxRequests()) {
                    response.setHeader("Retry-After", String.valueOf(Math.max(1, limit.window().toSeconds())));
                    problem(response, HttpStatus.TOO_MANY_REQUESTS, "Too many login attempts");
                    return;
                }
            } catch (DataAccessException e) {
                log.warn("Rate limiting del login non disponibile: {}", e.toString());
            }
            chain.doFilter(request, response);
        }
    }
}
