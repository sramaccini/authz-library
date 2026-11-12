package com.logicwarez.authz.rbac;

import java.time.Clock;

import javax.sql.DataSource;

import com.logicwarez.authz.rbac.admin.RbacAdminController;
import com.logicwarez.authz.rbac.admin.RbacAdminExceptionHandler;
import com.logicwarez.authz.rbac.admin.RbacAdminRepository;
import com.logicwarez.authz.rbac.admin.RbacAdminService;
import com.logicwarez.authz.rbac.directory.DirectoryController;
import com.logicwarez.authz.rbac.directory.TenantDirectory;
import com.logicwarez.authz.rbac.repository.AuthorizationRepository;
import com.logicwarez.authz.rbac.service.AuthorizationContext;
import com.logicwarez.authz.rbac.service.AuthorizationService;
import com.logicwarez.authz.rbac.token.PersonalAccessTokenController;
import com.logicwarez.authz.rbac.token.PersonalAccessTokens;
import com.logicwarez.authz.session.AuthorizationResolver;
import com.logicwarez.authz.session.SessionContext;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Modello RBAC in-process: ruoli e permessi per tenant, API di amministrazione /api/v1/admin/**,
 * migrazioni dello schema con una history Flyway propria. La protezione delle rotte di amministrazione
 * resta all'applicazione (vedi {@link RbacAdminSecurity}).
 */
@AutoConfiguration(after = DataSourceAutoConfiguration.class)
@EnableConfigurationProperties(RbacProperties.class)
@Import({AuthorizationRepository.class, AuthorizationService.class,
        RbacAdminRepository.class, RbacAdminService.class,
        RbacAdminController.class, RbacAdminExceptionHandler.class})
public class RbacAutoConfiguration {

    @Bean
    RbacSchemaMigrator rbacSchemaMigrator(DataSource dataSource, RbacProperties properties) {
        return new RbacSchemaMigrator(dataSource, properties.flyway(), properties.schema());
    }

    @Bean
    RbacJdbc rbacJdbc(JdbcClient jdbc, RbacProperties properties) {
        return new RbacJdbc(jdbc, properties.schema());
    }

    @Bean
    TenantDirectory tenantDirectory(RbacJdbc jdbc) {
        return new TenantDirectory(jdbc);
    }

    @Bean
    @ConditionalOnProperty("authz.rbac.directory.permission")
    DirectoryController directoryController(TenantDirectory directory, RbacProperties properties) {
        return new DirectoryController(directory, properties.directory().permission());
    }

    @Bean
    @ConditionalOnProperty(name = "authz.rbac.tokens.enabled", havingValue = "true")
    PersonalAccessTokens personalAccessTokens(RbacJdbc jdbc, RbacProperties properties) {
        return new PersonalAccessTokens(jdbc, properties.tokens(), Clock.systemUTC());
    }

    @Bean
    @ConditionalOnProperty(name = "authz.rbac.tokens.enabled", havingValue = "true")
    PersonalAccessTokenController personalAccessTokenController(PersonalAccessTokens tokens) {
        return new PersonalAccessTokenController(tokens);
    }

    @Bean
    @ConditionalOnMissingBean
    AuthorizationResolver authorizationResolver(AuthorizationService service) {
        return new AuthorizationResolver() {
            @Override
            public Resolved resolve(String username, String tenant) {
                return resolved(service.resolve(username, tenant, true));
            }

            @Override
            public Resolved resolveForToken(String username, String tenant) {
                return resolved(service.resolve(username, tenant, false));
            }
        };
    }

    private static AuthorizationResolver.Resolved resolved(AuthorizationContext ctx) {
        return new AuthorizationResolver.Resolved(ctx.username(), ctx.email(), ctx.tenantId(),
                ctx.availableTenants().entrySet().stream()
                        .map(t -> new SessionContext.Tenant(t.getKey(), t.getValue())).toList(),
                ctx.roles().stream().toList(), ctx.permissions().stream().toList());
    }
}
