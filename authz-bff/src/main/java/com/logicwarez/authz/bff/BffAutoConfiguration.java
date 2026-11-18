package com.logicwarez.authz.bff;

import java.time.Clock;

import com.logicwarez.authz.session.AuthorizationResolver;
import com.logicwarez.authz.session.PermissionContributor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.SupplierJwtDecoder;

/** Componenti del BFF incorporato; si collegano alla sicurezza con {@link BffConfigurer}. */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(BffProperties.class)
@Import({BffControllers.LoginController.class, BffControllers.SessionController.class,
        BffControllers.SessionAdminController.class, UserSessions.UserSessionController.class, AuthzController.class})
public class BffAutoConfiguration {

    /** Nome del decoder dei token di authz.bff.bearer: un JwtDecoder dell'applicazione non lo sostituisce. */
    public static final String BEARER_DECODER = "authzBearerJwtDecoder";

    /** Nome del decoder dei logout token di authz.bff.backchannel-logout. */
    public static final String LOGOUT_DECODER = "authzLogoutTokenDecoder";

    @Bean
    EffectivePermissions effectivePermissions(ObjectProvider<PermissionContributor> contributors) {
        return new EffectivePermissions(contributors.orderedStream().toList());
    }

    /**
     * Decoder degli access token dello IAM per authz.bff.bearer, creato al primo token (l'applicazione parte anche
     * con lo IAM spento). Un bean con lo stesso nome lo sostituisce (per esempio nei test).
     */
    @Bean(BEARER_DECODER)
    @ConditionalOnProperty(name = "authz.bff.bearer.enabled", havingValue = "true")
    @ConditionalOnMissingBean(name = BEARER_DECODER)
    JwtDecoder authzBearerJwtDecoder(ClientRegistrationRepository registrations, BffProperties properties) {
        return new SupplierJwtDecoder(() -> {
            BffProperties.Bearer bearer = properties.bearer();
            String issuer = bearer.issuerUri() != null ? bearer.issuerUri().toString()
                    : registrations.findByRegistrationId(properties.oidc().registrationId())
                            .getProviderDetails().getIssuerUri();
            if (issuer == null) {
                throw new IllegalStateException("authz.bff.bearer.issuer-uri mancante e provider OIDC senza issuer-uri");
            }
            NimbusJwtDecoder decoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(issuer);
            OAuth2TokenValidator<Jwt> client = token -> bearer.allowedClients().isEmpty()
                    || bearer.allowedClients().contains(token.getClaimAsString("azp"))
                    ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Token of another client", null));
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer), client));
            return decoder;
        });
    }

    /** Decoder dei logout token: chiavi, emittente e client della registrazione OIDC del login; creato al primo uso. */
    @Bean(LOGOUT_DECODER)
    @ConditionalOnProperty(name = "authz.bff.backchannel-logout.enabled", havingValue = "true")
    @ConditionalOnMissingBean(name = LOGOUT_DECODER)
    JwtDecoder authzLogoutTokenDecoder(ClientRegistrationRepository registrations, BffProperties properties) {
        return new SupplierJwtDecoder(() -> {
            ClientRegistration registration = registrations.findByRegistrationId(properties.oidc().registrationId());
            ClientRegistration.ProviderDetails provider = registration.getProviderDetails();
            if (provider.getJwkSetUri() == null || provider.getIssuerUri() == null) {
                throw new IllegalStateException("Back-channel logout: provider OIDC senza jwk-set-uri o issuer-uri");
            }
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(provider.getJwkSetUri()).validateType(false).build();
            decoder.setJwtValidator(BackChannelLogout.validator(provider.getIssuerUri(), registration.getClientId()));
            return decoder;
        });
    }

    @Bean
    @ConditionalOnProperty(name = "authz.bff.backchannel-logout.enabled", havingValue = "true")
    BackChannelLogout.SessionIndex backChannelSessionIndex(StringRedisTemplate redis, BffProperties properties) {
        return new BackChannelLogout.SessionIndex(redis, properties.backchannelLogout().redisKeyPrefix(),
                properties.session().absoluteTimeout());
    }

    @Bean
    @ConditionalOnProperty(name = "authz.bff.backchannel-logout.enabled", havingValue = "true")
    BackChannelLogout.BackChannelLogoutController backChannelLogoutController(
            @Qualifier(LOGOUT_DECODER) JwtDecoder decoder, BackChannelLogout.SessionIndex index,
            ObjectProvider<FindByIndexNameSessionRepository<? extends Session>> sessions) {
        return new BackChannelLogout.BackChannelLogoutController(decoder, index, sessions);
    }

    @Bean
    @ConditionalOnProperty(name = "authz.bff.token-relay.enabled", havingValue = "true")
    SessionAccessTokens sessionAccessTokens(ClientRegistrationRepository registrations, BffProperties properties) {
        return new SessionAccessTokens(registrations, properties, Clock.systemUTC());
    }

    @Bean
    LoginSupport.LoginRedirects loginRedirects(BffProperties properties) {
        return new LoginSupport.LoginRedirects(properties);
    }

    @Bean
    LoginSupport.Origins origins(BffProperties properties) {
        return new LoginSupport.Origins(properties);
    }

    @Bean
    LoginSupport.OriginPolicy originPolicy(LoginSupport.Origins origins) {
        return new LoginSupport.OriginPolicy(origins);
    }

    @Bean
    LoginSupport.IamLogout iamLogout(ClientRegistrationRepository registrations, BffProperties properties) {
        return new LoginSupport.IamLogout(registrations, properties);
    }

    @Bean
    LoginSupport.LoginSuccessHandler loginSuccessHandler(AuthorizationResolver resolver,
                                                         ObjectProvider<OAuth2AuthorizedClientRepository> clients,
                                                         LoginSupport.LoginRedirects redirects,
                                                         BffProperties properties,
                                                         ObjectProvider<BackChannelLogout.SessionIndex> sessionIndex) {
        return new LoginSupport.LoginSuccessHandler(resolver, clients, redirects, properties, Clock.systemUTC(),
                sessionIndex.getIfAvailable());
    }

    @Bean
    LoginSupport.LoginFailureHandler loginFailureHandler(LoginSupport.LoginRedirects redirects) {
        return new LoginSupport.LoginFailureHandler(redirects);
    }
}
