package com.logicwarez.authz.rbac;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * @param flyway    migrazioni dello schema RBAC, indipendenti da quelle dell'applicazione che incorpora la libreria
 * @param schema    schema PostgreSQL delle tabelle RBAC (creato dalle migrazioni); vuoto: lo schema predefinito della
 *                  connessione, come fino alla 2.1. Cambiarlo su un database esistente non sposta i dati.
 * @param directory elenco in sola lettura degli utenti del tenant per l'interfaccia
 * @param tokens    token di accesso personali
 */
@ConfigurationProperties("authz.rbac")
public record RbacProperties(@DefaultValue Flyway flyway, String schema, @DefaultValue Directory directory,
                             @DefaultValue Tokens tokens) {

    /**
     * @param locations  script SQL; in sviluppo si aggiungono i dati demo (es. classpath:db/authz/seed)
     * @param table      history table dedicata: le versioni non si scontrano con quelle dell'applicazione
     * @param outOfOrder ammesso solo in sviluppo, quando i seed hanno versioni piu' alte dello schema
     */
    public record Flyway(@DefaultValue("true") boolean enabled,
                         @DefaultValue("classpath:db/authz/migration") List<String> locations,
                         @DefaultValue("authz_schema_history") String table,
                         @DefaultValue("false") boolean outOfOrder) {
    }

    /**
     * {@code GET /api/v1/directory/users}: utenti attivi del tenant della sessione, per i selettori dell'interfaccia.
     *
     * @param permission permesso dell'applicazione richiesto per leggere l'elenco; vuoto: endpoint non esposto (il
     *                   servizio {@code TenantDirectory} resta disponibile al codice dell'applicazione)
     */
    public record Directory(String permission) {
    }

    /**
     * Token di accesso personali ({@code /api/v1/tokens}), accettati da {@code authz.bff.bearer}.
     *
     * @param enabled    endpoint e verifica dei token; spento: i token esistenti non sono accettati
     * @param maxPerUser token attivi (non revocati, non scaduti) per utente
     * @param maxDays    durata massima di un token, in giorni
     */
    public record Tokens(@DefaultValue("false") boolean enabled,
                         @DefaultValue("20") int maxPerUser,
                         @DefaultValue("366") int maxDays) {
    }
}
