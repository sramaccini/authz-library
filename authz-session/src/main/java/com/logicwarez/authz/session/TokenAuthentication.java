package com.logicwarez.authz.session;

/**
 * Utente autenticato da un token ({@code Authorization: Bearer}) invece che da una sessione: stesso
 * {@link SessionContext} e stesse authority, ricostruiti a ogni richiesta e mai salvati. Chi legge
 * {@link SessionAuthentication} funziona senza cambiamenti; chi deve distinguere (per esempio le operazioni concesse
 * solo dal browser) controlla questo tipo.
 */
public class TokenAuthentication extends SessionAuthentication {

    /** Token di accesso personale invece di un token dello IAM. */
    public static final String PERSONAL_ACCESS_TOKEN = "personal-access-token";

    private final String client;

    /** @param client client che ha ottenuto il token ({@code azp}) o {@link #PERSONAL_ACCESS_TOKEN} */
    public TokenAuthentication(SessionContext session, String client) {
        super(session);
        this.client = client;
    }

    public String client() {
        return client;
    }
}
