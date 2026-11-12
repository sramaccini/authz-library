package com.logicwarez.authz.rbac;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * JdbcClient delle tabelle RBAC: con {@code authz.rbac.schema} impostato qualifica le tabelle con lo schema
 * (dopo FROM, JOIN, INTO, UPDATE), cosi' le query non dipendono dal search_path dell'applicazione. Senza schema le
 * query restano come sono (schema predefinito della connessione, come fino alla 2.1).
 */
public class RbacJdbc {

    /** Tabelle create dalle migrazioni di authz-rbac. */
    private static final Pattern TABLE = Pattern.compile(
            "(?i)\\b(FROM|JOIN|INTO|UPDATE)(\\s+)(app_user|app_role|app_permission|role_permission|user_role|tenant"
                    + "|rbac_audit|personal_access_token)\\b");
    private static final Pattern SCHEMA = Pattern.compile("^[a-z_][a-z0-9_]{0,62}$");

    private final JdbcClient jdbc;
    private final String schema;
    private final Map<String, String> qualified = new ConcurrentHashMap<>();

    public RbacJdbc(JdbcClient jdbc, String schema) {
        if (schema != null && !schema.isBlank() && !SCHEMA.matcher(schema).matches()) {
            throw new IllegalArgumentException("authz.rbac.schema non valido: " + schema);
        }
        this.jdbc = jdbc;
        this.schema = schema == null || schema.isBlank() ? null : schema;
    }

    public JdbcClient.StatementSpec sql(String sql) {
        return jdbc.sql(schema == null ? sql : qualified.computeIfAbsent(sql, this::qualify));
    }

    String qualify(String sql) {
        return TABLE.matcher(sql).replaceAll(m -> Matcher.quoteReplacement(
                m.group(1) + m.group(2) + schema + "." + m.group(3)));
    }
}
