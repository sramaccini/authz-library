-- Token di accesso personali: solo l'hash SHA-256 del token, mostrato una volta alla creazione.
CREATE TABLE personal_access_token (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES app_user (id) ON DELETE CASCADE,
    name         VARCHAR(100) NOT NULL,
    token_hash   CHAR(64) NOT NULL UNIQUE,
    token_hint   VARCHAR(12) NOT NULL,
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   TIMESTAMP WITH TIME ZONE NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked_at   TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_personal_access_token_user ON personal_access_token (user_id);
