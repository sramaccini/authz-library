package com.logicwarez.authz.session;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Punto di estensione per i permessi che l'RBAC per tenant non conosce, per esempio quelli che dipendono da un
 * progetto. Uno o piu' bean dell'applicazione; senza, {@code /authz/capabilities} e {@code /authz/check} usano solo i
 * permessi della sessione.
 * <ul>
 *   <li>{@link #permissions} si aggiunge ai permessi della sessione in {@code /authz/capabilities} e nella versione
 *       dei permessi ({@code X-Permissions-Version}), che e' calcolata a ogni risposta autenticata: deve essere
 *       veloce (in memoria o con una cache dell'applicazione).</li>
 *   <li>{@link #check} decide i controlli di {@code /authz/check} che hanno una risorsa; il primo contributor che
 *       risponde decide, altrimenti vale il permesso della sessione.</li>
 * </ul>
 * Riguarda il contratto con la UI: le API dell'applicazione fanno comunque i propri controlli.
 */
public interface PermissionContributor {

    /** Permessi in piu' dell'utente, indipendenti da una risorsa. */
    default Collection<String> permissions(SessionContext session) {
        return List.of();
    }

    /**
     * @param resource risorsa del controllo, mai null
     * @return la decisione, vuoto se il contributor non riguarda questa risorsa o questo permesso
     */
    default Optional<Boolean> check(SessionContext session, String permission, Resource resource) {
        return Optional.empty();
    }

    /** Risorsa di un controllo ({@code ResourceRef} del contratto authz.yaml di Quadrava). */
    record Resource(String type, String id) {
    }
}
