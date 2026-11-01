package com.logicwarez.authz.session;

import java.io.IOException;
import java.time.Clock;
import java.util.Optional;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Autentica la richiesta con il {@link SessionContext} della sessione HTTP.
 * Sessione assente: la richiesta prosegue non autenticata (Spring Security risponde 401).
 * Sessione oltre la scadenza assoluta: invalidata. Session store non raggiungibile: 503.
 * Gira anche negli error dispatch (verso /error) e negli async dispatch (stream di eventi, Callable): senza, la
 * regola di autorizzazione li vedrebbe non autenticati e un 404 o una risposta asincrona diventerebbero 401.
 */
public class SessionContextFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(SessionContextFilter.class);

    private final Clock clock;
    private final SecurityContextHolderStrategy contextHolder = SecurityContextHolder.getContextHolderStrategy();

    public SessionContextFilter(Clock clock) {
        this.clock = clock;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<SessionContext> session;
        try {
            session = current(request);
        } catch (DataAccessException e) {
            log.error("Session store non raggiungibile: {}", e.toString());
            response.setStatus(HttpStatus.SERVICE_UNAVAILABLE.value());
            response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
            response.getWriter().write("""
                    {"type":"about:blank","title":"Service Unavailable","status":503,"detail":"Service temporarily unavailable"}""");
            return;
        }
        session.ifPresent(s -> {
            SecurityContext context = contextHolder.createEmptyContext();
            context.setAuthentication(new SessionAuthentication(s));
            contextHolder.setContext(context);
        });
        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilterAsyncDispatch() {
        return false;
    }

    @Override
    protected boolean shouldNotFilterErrorDispatch() {
        return false;
    }

    @Override
    protected void doFilterNestedErrorDispatch(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        doFilterInternal(request, response, chain);
    }

    private Optional<SessionContext> current(HttpServletRequest request) {
        HttpSession httpSession = request.getSession(false);
        if (httpSession == null) {
            return Optional.empty();
        }
        Optional<SessionContext> context = SessionContext.from(httpSession);
        if (context.isPresent() && context.get().isExpiredAt(clock.instant())) {
            httpSession.invalidate();
            return Optional.empty();
        }
        return context;
    }
}
