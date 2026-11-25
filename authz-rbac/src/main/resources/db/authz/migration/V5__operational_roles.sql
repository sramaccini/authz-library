-- Ruoli operativi (contracts/bff.yaml 0.6.0 e authz.yaml 0.2.0 di Quadrava, ADR-28): un ruolo di base vale sempre,
-- quelli operativi si scelgono uno alla volta e i permessi sono quelli dei ruoli di base piu' quello attivo.
-- Ogni ruolo esistente resta di base: chi non segna ruoli operativi ha i permessi di sempre (tutti i ruoli).
ALTER TABLE app_role
    ADD COLUMN is_base BOOLEAN NOT NULL DEFAULT TRUE;

-- Ultimo ruolo operativo usato: al login l'utente entra su questo, senza domande, se lo ha ancora sul tenant.
ALTER TABLE app_user
    ADD COLUMN last_role_code VARCHAR(100) REFERENCES app_role (role_code) ON DELETE SET NULL;
