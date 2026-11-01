# HANDOFF — ms-authz (librerie)

Note per chi continua il lavoro. Leggi prima `README.md` (moduli, contratto con il front end, avvio locale) e
`CHANGELOG.md`. Fonte dei requisiti originari: `docs/specifiche_architetturali_bff_auth_service.md`.
L'utente è Simone. Lavora in italiano, tono tecnico.

## Stato

**2026-11-01 — 2.1.0** (test di integrazione, OpenAPI generata, sessioni di altre versioni, errori in inglese; 2.0.0 e 2.0.1 il 2026-10-31), groupId e package `com.logicwarez.authz` (le pubblicazioni dello stesso giorno con `com.enterprise.authz` 2.0.0 e `it.logicware.authz` 3.0.0 sono ritirate). Repository github.com/sramaccini/authz-library, branch `master`. Le librerie
(`authz-session`, `authz-rbac`, `authz-bff`, esempio `examples/authz-demo-app`) hanno sostituito i servizi della 1.x,
eliminati su indicazione dell'utente (erano in `legacy/`; restano nella storia git fino al commit `0074f15`).

Fatto il 2026-10-31, su richiesta di Quadrava (`PiattaformaLowCode/docs/handoff-opendevtrack.md`, sezione "What
ms-authz must adapt", punti 1-8; prima consumatrice OpenDevTrack):
1. `POST /logout` → `{"redirect"}`; 2. `/bff/login?return=` con verifica dell'origine (`400` Problem);
3. `/authz/capabilities` e `/authz/check`; 4. permessi `dominio.risorsa.azione` (migrazione `V3`);
5. `401` senza sessione, CSRF `XSRF-TOKEN`/`X-XSRF-TOKEN`, `X-Permissions-Version` su ogni risposta;
6. `tenants`/`currentTenant` in `/bff/user`, `POST /bff/tenant`, login sull'ultimo tenant usato;
7. stream di eventi: solo configurazione (`spring.mvc.async.request-timeout: -1`), documentata;
8. `server.forward-headers-strategy=framework` documentato, origine pubblica del BFF ammessa come `return`.

Verifiche: 42 test con `mvn install`. `BffContractTest` prova il contratto via HTTP; `RbacPostgresTest` e
`BffRedisTest` usano PostgreSQL e Redis veri con Testcontainers (serve Docker, altrimenti sono saltati);
`AdminOpenApiTest` rigenera la definizione OpenAPI e fallisce se `docs/authz-admin-openapi-spec.json` non è
aggiornata. Il 2026-10-31, prova
end-to-end con Keycloak, Redis e PostgreSQL reali e l'app demo: kit `conformance:bff` di Quadrava 13/13 con e senza
sessione, ultimo tenant ricordato tra due login, logout con `id_token_hint`, revoca delle sessioni, escalation del
delegato bloccata. Trovato e corretto nell'end-to-end: con Boot 4 le proprietà `spring.session.redis.*` sono
ignorate (la revoca rispondeva sempre `501`); si usano `spring.session.data.redis.*`.

## Ambiente di questa macchina

- JDK 25: `C:\Program Files\Eclipse Adoptium\jdk-25.0.5.8-hotspot` (non è nel PATH: `java` è la 21).
  `export JAVA_HOME="/c/Program Files/Eclipse Adoptium/jdk-25.0.5.8-hotspot"`.
- `TEMP` in formato corto 8.3: `export JAVA_TOOL_OPTIONS='-Djdk.net.unixdomain.tmpdir=C:\tmp\ud'` prima di `mvn`, e
  `-Djdk.net.unixdomain.tmpdir=C:\tmp\ud` per avviare l'app. Problema della macchina: non va nei pom.
- Node non è nel PATH: `~/AppData/Roaming/fnm/node-versions/v24.22.0/installation/node.exe` (per i kit di Quadrava).
- Niente `gh` e niente Python.
- Sulle porte 8180 (Keycloak) e 8090 (`quadrava-runtime`) girano container di altri progetti: per l'end-to-end si
  usa un progetto compose separato con porte spostate (`docker compose -p authzlib -f docker-compose.yml -f <override>`,
  Keycloak 18180, PostgreSQL 15432, Redis 16379; `.env` con valori di test generati, gitignored).
- Commit solo a nome dell'utente, `Simone Ramaccini <s.ramaccini@gmail.com>` (impostato nel `git config` del repo:
  quello globale ha un altro indirizzo): unico autore, nessun trailer `Co-Authored-By` né altre attribuzioni, in
  commit, tag, release, file e note.

## Decisioni prese (non cambiarle senza parlarne con l'utente)

1. **Librerie da incorporare**, non servizi: BFF, RBAC e API nello stesso processo; niente `X-Session-ID` né gateway.
2. **Contratti di Quadrava**: nomi e forme li decide Quadrava (`contracts/bff.yaml`, `authz.yaml`); ms-authz si
   adegua. Quadrava non va modificata da questa sessione.
3. **Sessione Spring Session su Redis** (`repository-type: indexed`, per la revoca), cookie `HttpOnly`,
   `SameSite=Lax` (il ritorno dallo IAM è cross-site). Timeout di inattività scorrevole più scadenza assoluta
   (`authz.bff.session.absolute-timeout`). Il SecurityContext non va in sessione: si ricostruisce dal `SessionContext`.
4. **CSRF a token** (Spring `csrf.spa()`, cookie `XSRF-TOKEN` leggibile) più controllo `Origin` come difesa in
   profondità: un `Origin` estraneo dà `403`, un `Origin` assente decide il solo token.
5. **Pagina di ritorno del login** solo nelle origini `authz.bff.frontend.allowed-origins` o nell'origine pubblica
   del BFF (niente open redirect).
6. **Tenant**: il login non chiede mai il tenant (ultimo usato, poi il primo per codice); il cambio è
   `POST /bff/tenant`, mai GET. Il cambio non rigenera l'id di sessione e mantiene la scadenza assoluta del login.
7. **Permessi** `dominio.risorsa.azione`, minuscolo, senza trattini; quelli che finiscono in `global` sono solo di
   `GLOBAL_ADMIN`. Vincolo `ck_permission_code_format` `NOT VALID` (non blocca dati esistenti in altro formato).
8. **Versione dei permessi**: primi 16 caratteri esadecimali dello SHA-256 dei permessi ordinati; `app` di
   `/authz/capabilities` è obbligatorio ma non filtra (come nell'implementazione di riferimento di Quadrava).
9. Utente inesistente, disattivato o senza ruoli → `access_denied` (niente user enumeration).
10. Accesso al DB con JdbcClient (niente JPA); Flyway con history propria `authz_schema_history`; dati demo solo nel
    profilo `dev` dell'esempio (`out-of-order` perché i seed hanno versioni V99+).
11. **Amministrazione RBAC**: amministratori delegati per tenant e globale; catalogo dei permessi solo da
    migrazioni; ruoli di sistema non modificabili; nessuno modifica la propria utenza; audit in `rbac_audit` nella
    stessa transazione; effetto al login successivo, revoca per l'effetto immediato.
12. **Logout sullo IAM** (RP-initiated, `id_token_hint`): l'ID token resta in sessione, access e refresh token no.
13. **Rate limiting del login**: per IP, contatore su Redis, fail-open.
14. **Distribuzione**: GitHub Packages (Maven) dal workflow `release.yml` su tag `vX.Y.Z` uguale alla versione dei
    pom; l'esempio non si pubblica. groupId e package Java `com.logicwarez.authz` (decisione dell'utente).

## Prossimi passi suggeriti

1. Back-channel logout OIDC: revoca delle sessioni quando l'utente esce dallo IAM da un'altra applicazione.
2. Retention e protezione del registro di audit (GDPR).
3. Valutare un BOM (`authz-bom`) se le applicazioni consumatrici diventano più di una.
4. Il `type` dei Problem dell'API di amministrazione è ancora `urn:problem:auth-service:<codice>` (nome della 1.x):
   cambiarlo è una modifica del contratto, da concordare con chi lo usa.
