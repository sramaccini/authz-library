package com.logicwarez.authz.rbac;

import javax.sql.DataSource;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.springframework.beans.factory.InitializingBean;

/**
 * Applica le migrazioni RBAC all'avvio con un'istanza Flyway privata. Non e' un bean di tipo Flyway:
 * altrimenti la configurazione automatica di Spring Boot disattiverebbe il Flyway dell'applicazione.
 */
public class RbacSchemaMigrator implements InitializingBean {

    private final DataSource dataSource;
    private final RbacProperties.Flyway properties;
    private final String schema;

    public RbacSchemaMigrator(DataSource dataSource, RbacProperties.Flyway properties, String schema) {
        this.dataSource = dataSource;
        this.properties = properties;
        this.schema = schema == null || schema.isBlank() ? null : schema;
    }

    @Override
    public void afterPropertiesSet() {
        if (!properties.enabled()) {
            return;
        }
        FluentConfiguration flyway = Flyway.configure()
                .dataSource(dataSource)
                .locations(properties.locations().toArray(String[]::new))
                .table(properties.table())
                .outOfOrder(properties.outOfOrder())
                // Schema gia' usato dall'applicazione: si parte da zero senza rifiutare uno schema non vuoto
                .baselineOnMigrate(true)
                .baselineVersion("0");
        if (schema != null) {
            // Schema creato se manca; history e tabelle in quello schema (search_path delle migrazioni)
            flyway.schemas(schema).defaultSchema(schema);
        }
        flyway.load().migrate();
    }
}
