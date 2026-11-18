package com.logicwarez.authz.bff;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import com.logicwarez.authz.session.AuthorizationResolver;
import com.logicwarez.authz.session.SessionContext;
import com.logicwarez.authz.session.TenantSelectionRequiredException;
import com.logicwarez.authz.session.UserNotAuthorizedException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.session.FindByIndexNameSessionRepository;

import static org.assertj.core.api.Assertions.assertThat;

class LoginSuccessHandlerTest {

    private static final Instant NOW = Instant.parse("2026-10-30T10:00:00Z");

    private final BffProperties properties = new BffProperties(
            new BffProperties.Oidc("iam", "preferred_username", "name"),
            new BffProperties.Session(Duration.ofHours(10)),
            new BffProperties.Frontend(URI.create("https://app/"), URI.create("https://app/login-error"),
                    URI.create("https://app/"), List.of("https://app")),
            new BffProperties.LoginRateLimit(true, 20, Duration.ofMinutes(1), "rl:"),
            new BffProperties.Bearer(false, List.of(), null, List.of(), "X-Tenant",
                    new BffProperties.RateLimit(true, 600, Duration.ofMinutes(1), "rb:")),
            new BffProperties.BackchannelLogout(false, "oidc:"),
            new BffProperties.RecentLogin(Duration.ofMinutes(15), List.of()),
            new BffProperties.SessionRateLimit(false, List.of("/api/**"), 600, Duration.ofMinutes(1), "rs:"));

    private MockHttpServletResponse login(AuthorizationResolver resolver, MockHttpServletRequest request)
            throws Exception {
        var handler = new LoginSupport.LoginSuccessHandler(resolver,
                new StaticListableBeanFactory().getBeanProvider(OAuth2AuthorizedClientRepository.class),
                new LoginSupport.LoginRedirects(properties), properties, Clock.fixed(NOW, ZoneOffset.UTC));
        var user = new DefaultOAuth2User(AuthorityUtils.NO_AUTHORITIES,
                Map.of("preferred_username", "mario.rossi", "name", "Mario Rossi"), "preferred_username");
        var response = new MockHttpServletResponse();
        handler.onAuthenticationSuccess(request, response, new OAuth2AuthenticationToken(user, List.of(), "iam"));
        return response;
    }

    @Test
    void salvaIlContestoInSessioneConTenantScelto() throws Exception {
        var request = new MockHttpServletRequest();
        request.getSession().setAttribute(LoginSupport.TENANT_HINT, "TENANT_B");
        var response = login((u, t) -> new AuthorizationResolver.Resolved(u, "m@x.it", t,
                List.of(new SessionContext.Tenant(t, "Sede B")), List.of("DOCTOR"), List.of("clinical.patient.read")), request);

        SessionContext ctx = (SessionContext) request.getSession().getAttribute(SessionContext.ATTRIBUTE);
        assertThat(ctx.tenantId()).isEqualTo("TENANT_B");
        assertThat(ctx.permissions()).containsExactly("clinical.patient.read");
        assertThat(ctx.expiresAt()).isEqualTo(NOW.plus(Duration.ofHours(10)));
        assertThat(request.getSession().getAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME))
                .isEqualTo("mario.rossi");
        assertThat(request.getSession().getAttribute(LoginSupport.TENANT_HINT)).isNull();
        assertThat(ctx.name()).isEqualTo("Mario Rossi");
        assertThat(ctx.tenants()).containsExactly(new SessionContext.Tenant("TENANT_B", "Sede B"));
        assertThat(response.getRedirectedUrl()).isEqualTo("https://app/");
    }

    @Test
    void tornaAllaPaginaIndicataDaBffLogin() throws Exception {
        var request = new MockHttpServletRequest();
        request.getSession().setAttribute(LoginSupport.RETURN_TO, "https://app/board?id=7");
        var response = login((u, t) -> new AuthorizationResolver.Resolved(u, null, "T", List.of(), List.of()), request);
        assertThat(response.getRedirectedUrl()).isEqualTo("https://app/board?id=7");
        assertThat(request.getSession().getAttribute(LoginSupport.RETURN_TO)).isNull();
    }

    @Test
    void utenteNonAbilitatoInvalidaLaSessione() throws Exception {
        var request = new MockHttpServletRequest();
        var session = request.getSession();
        var response = login((u, t) -> { throw new UserNotAuthorizedException("no"); }, request);
        assertThat(response.getRedirectedUrl()).isEqualTo("https://app/login-error?error=access_denied");
        assertThat(request.getSession(false)).isNotSameAs(session);
    }

    @Test
    void piuTenantSenzaSceltaChiedeLaSelezione() throws Exception {
        var response = login((u, t) -> { throw new TenantSelectionRequiredException(new TreeSet<>(List.of("A", "B"))); },
                new MockHttpServletRequest());
        assertThat(response.getRedirectedUrl()).isEqualTo("https://app/login-error?error=tenant_selection_required");
    }

    @Test
    void sessioneOltreLaScadenzaAssolutaNonVale() {
        var ctx = new SessionContext("u", null, null, "T", List.of(), List.of(), List.of(), NOW, NOW.plusSeconds(60));
        assertThat(ctx.isExpiredAt(NOW.plusSeconds(59))).isFalse();
        assertThat(ctx.isExpiredAt(NOW.plusSeconds(60))).isTrue();
    }
}
