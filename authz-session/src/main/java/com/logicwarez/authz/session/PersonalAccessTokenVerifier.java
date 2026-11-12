package com.logicwarez.authz.session;

import java.time.Instant;
import java.util.Optional;

/**
 * Verifica un token di accesso personale presentato come {@code Authorization: Bearer}. Implementato da
 * {@code authz-rbac}; senza un bean di questo tipo il BFF accetta solo i token dello IAM.
 */
public interface PersonalAccessTokenVerifier {

    /** Prefisso dei token di accesso personali: distingue a colpo d'occhio un token personale da un JWT. */
    String PREFIX = "pat_";

    /** @return utente e scadenza del token, vuoto se il token e' sconosciuto, revocato o scaduto */
    Optional<Owner> verify(String token);

    record Owner(String username, Instant expiresAt) {
    }
}
