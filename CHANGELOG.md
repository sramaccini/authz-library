# Changelog

Formato [Keep a Changelog](https://keepachangelog.com/it/1.1.0/), versioni [Semantic Versioning](https://semver.org/lang/it/).

## [2.6.0] - 2026-11-19

Richiesta A10 di OpenDevTrack (GDPR, ASVS 8.3.2; issue sramaccini/open-devtrack#24). Nessuna migrazione.

### Aggiunto

- `RbacAdminService.forgetUser(actor, tenant, username, pseudonym)` e
  `POST /api/v1/admin/tenants/{tenant}/users/{username}/forget`. Nelle voci di audit del tenant il nome diventa lo
  pseudonimo, in autore, oggetto e valori JSON. Se l'utente non ha più ruoli su nessun tenant, elimina la riga
  `app_user` con i token personali e pseudonimizza anche le voci senza tenant. Scrive una voce `USER_FORGOTTEN` con
  il solo pseudonimo. Le regole sono quelle di `replaceUserRoles`, e l'utente non deve avere ruoli sul tenant.
  Partecipa alla transazione del chiamante.
- `RbacAdminService.findUser(actor, username)`: un `Optional` che non lancia eccezioni per un utente sconosciuto.
- Test in `RbacPostgresTest`.

### Modificato

- Login: se l'`AuthorizationResolver` non restituisce l'email (resolver che conosce solo lo username), la sessione
  usa il claim `email` dello IAM; il cambio di tenant mantiene quella della sessione. Segnalazione di Quadrava.
- README, token relay: non copiare l'`X-Permissions-Version` della risposta di un servizio inoltrato.

## [2.5.0] - 2026-11-18

### Aggiunto

- Licenza **Mozilla Public License 2.0** (`LICENSE`, `<licenses>` nel `pom.xml`): le librerie si possono usare, anche in Quadrava CE.
- **Token relay** (richiesta di Quadrava CE per il BFF di riferimento): con `authz.bff.token-relay.enabled: true`
  il login lascia nella sessione (Redis) il client autorizzato della registrazione OIDC, con access e refresh token,
  invece di eliminarlo. Il bean `SessionAccessTokens` dà l'access token dell'utente della sessione
  (`forRequest(request, response)`), rinnovato con il refresh token se scade entro `clock-skew` (60s), per
  inoltrarlo a servizi separati. Vuoto senza sessione o se il rinnovo fallisce: refresh token scaduto o revocato →
  client tolto (serve un nuovo login), IAM non raggiungibile → client tenuto. I token finiscono con la sessione
  (logout, revoca, back-channel logout). Spento: comportamento invariato.
- Test: `BffTokenRelayTest` (Redis, token endpoint finto).

## [2.4.0] - 2026-11-18

Richieste A8 e A9 di OpenDevTrack (ASVS 3.7.1, 4.3.3, 11.1.4). Tutto facoltativo; nessuna modifica ai contratti
`bff.yaml` e `authz.yaml`, nessuna migrazione.

### Aggiunto

- **Login recente** (A8): `authz.bff.recent-login.paths` (con il metodo facoltativo, `POST /api/me/tokens`) e
  `max-age` (15m). Una sessione autenticata sullo IAM da più di `max-age` riceve su quei percorsi `401` con il
  Problem `urn:problem:authz:recent-login-required` (e `maxAge` in secondi). Al login la sessione registra
  `auth_time` dell'ID token.
- `/bff/login?max_age=<secondi>`: passa `max_age` allo IAM nella richiesta di autorizzazione, anche con una sessione
  già aperta. Verificato su Keycloak 26: con `max_age=0` chiede di nuovo la password dentro la sessione SSO e
  aggiorna `auth_time`. `400` per un valore non numerico.
- **Limite delle sessioni** (A9): `authz.bff.session-rate-limit` (`enabled`, `paths` `/api/**`, `max-requests` 600,
  `window` 1m, `redis-key-prefix` `authz:ratelimit:session:`): limite per utente sulle richieste delle sessioni del
  browser, `429` con `Retry-After`.
- Test: `BffGuardsTest` (Redis).

### Corretto

- I Problem scritti dai filtri del BFF (`401`, `403`, `429`...) avevano `charset=ISO-8859-1`; ora UTF-8.

## [2.3.0] - 2026-11-18

Richiesta A7 di OpenDevTrack (ASVS 3.3.3, 3.3.4). Nessuna modifica ai contratti `bff.yaml` e `authz.yaml`.

### Aggiunto

- **Sessioni dell'utente**: `GET /bff/sessions` (id opaco, creazione, ultimo accesso, IP e user agent del login,
  tenant, sessione corrente), `DELETE /bff/sessions/{id}`, `DELETE /bff/sessions` (tutte tranne la corrente).
  Al login la sessione registra IP, user agent, `sid` e `sub` dello IAM.
- **Back-channel logout OIDC**: con `authz.bff.backchannel-logout.enabled: true`, `POST /bff/backchannel-logout`
  chiude le sessioni del BFF collegate al `sid` (o al `sub`) del logout token dello IAM. Chiavi Redis
  `authz:oidc:` (`redis-key-prefix`) da `sid`/`sub` all'utente. Realm di sviluppo configurato (URL di
  back-channel, *session required*) e `extra_hosts` per Keycloak in `docker-compose.yml`; l'app demo lo attiva.
- `GET /bff/admin/users/{username}/sessions`: sessioni di un utente per l'amministrazione, con le regole della
  revoca.
- `/bff/backchannel-logout` in `BffControllers.PUBLIC_PATHS`.
- Test: `BffSessionsTest` (Redis, login con il `LoginSuccessHandler` vero, logout token firmati). Formato del
  logout token verificato su Keycloak 26.

## [2.2.0] - 2026-11-12

Richieste di OpenDevTrack (A1, A2, A4, A5, A6; A3 era già nella 2.1.0). Tutto facoltativo: senza nuove proprietà il
comportamento è quello della 2.1.0, a parte la migrazione `V4` applicata da `authz-rbac`. Nessuna modifica ai
contratti `bff.yaml` e `authz.yaml`.

### Aggiunto

- **Permessi dell'applicazione** (A1): i bean `PermissionContributor` (`authz-session`) aggiungono permessi alla
  sessione (`permissions(session)`, per esempio i ruoli di progetto) e decidono i controlli su una risorsa
  (`check(session, permission, resource)`; il primo che risponde decide). `/authz/capabilities`, `/authz/check` e
  `X-Permissions-Version` usano lo stesso insieme effettivo, così la versione cambia quando cambiano i permessi
  aggiunti dall'applicazione. Senza contributor la versione resta quella della 2.1.0.
- **Schema dedicato** (A2): `authz.rbac.schema: authz` mette tabelle e history delle migrazioni nello schema indicato
  (creato da Flyway se manca) e qualifica tutte le query della libreria; lo schema dell'applicazione resta suo.
- **Accesso con token** (A4): con `authz.bff.bearer.enabled: true` le richieste su `authz.bff.bearer.paths`
  (predefinito `/api/**`) possono usare `Authorization: Bearer <access token>` dello IAM al posto del cookie: firma,
  scadenza e issuer verificati (issuer della registrazione OIDC o `authz.bff.bearer.issuer-uri`), client ammessi in
  `allowed-clients` (claim `azp`, vuoto = tutti), tenant dall'header `X-Tenant` (predefinito l'ultimo usato, che il
  token non cambia), nessuna sessione creata, niente CSRF. Cookie e token insieme → `400`; token non valido o scaduto
  → `401` con `WWW-Authenticate: Bearer error="invalid_token"`; utente o tenant non autorizzato → `403`; limite per
  utente su Redis (`rate-limit.max-requests` in `rate-limit.window`, predefinito 600 al minuto) → `429` con
  `Retry-After`. L'`Authentication` è un `TokenAuthentication` (sottoclasse di `SessionAuthentication`, con
  `client()`): `@AuthenticationPrincipal SessionContext` e `@PreAuthorize` funzionano come con la sessione.
- **Directory del tenant** (A5): `TenantDirectory` (utenti attivi con almeno un ruolo sul tenant, `search` e
  `find`) e, con `authz.rbac.directory.permission: <permesso>`, `GET /api/v1/directory/users?q=&limit=` sul tenant
  della sessione.
- **Token di accesso personali** (A6): con `authz.rbac.tokens.enabled: true`, `GET/POST /api/v1/tokens` e
  `DELETE /api/v1/tokens/{id}` (solo da una sessione del browser). Il token `pat_…` si vede solo alla creazione; nel
  database c'è il suo SHA-256. Durata massima `max-days` (366, predefinita 90), al massimo `max-per-user` (20) token
  attivi, creazione e revoca nell'audit, token invalidati se l'utente è disattivato. Con l'accesso con token attivo
  il BFF li accetta come bearer (`client()` = `personal-access-token`).
- Migrazione `V4__personal_access_tokens.sql` (tabella `personal_access_token`).
- `AuthorizationResolver.resolveForToken(username, tenant)`, predefinito uguale a `resolve`; quello di `authz-rbac`
  non aggiorna l'ultimo tenant usato.
- Test: `BffBearerTest`, `BffBearerRateLimitTest` (Redis), `RbacSchemaTest` (PostgreSQL), contributor in
  `BffContractTest`, directory e token in `RbacPostgresTest`.

## [2.1.0] - 2026-11-01

Nessuna modifica ai contratti `bff.yaml` e `authz.yaml`: si aggiorna da 2.0.x cambiando solo la versione.

### Modificato

- Messaggi degli errori (`detail` dei Problem `application/problem+json`) in inglese, nel BFF, in `/authz/*`, nel
  filtro della sessione e nell'API di amministrazione. Il `title` era già la frase standard dello status HTTP; `type`
  e codici degli errori non cambiano.
- Realm Keycloak di sviluppo: il client `bff-gateway` accetta anche `http://localhost:8090` (ritorno dal login,
  origine e pagina dopo il logout), per l'immagine runtime di Quadrava.

### Aggiunto

- Test di integrazione con Testcontainers: `RbacPostgresTest` (PostgreSQL 17: migrazioni con la history propria,
  vincolo sul formato dei permessi, tenant del login e ultimo tenant usato, regole del delegato, audit, blocco
  ottimistico dei ruoli) e `BffRedisTest` (Redis 7.4: sessione indicizzata, revoca di tutte le sessioni di un utente,
  sessione di un'altra versione). Richiedono Docker; senza, sono saltati.
- `docs/authz-admin-openapi-spec.json` generata da springdoc (solo nei test) e verificata dal build:
  `AdminOpenApiTest` fallisce se la definizione non corrisponde al controller.

### Corretto

- `docs/authz-admin-openapi-spec.json` era ferma alla 1.x in alcuni punti: formato dei permessi `a:b` invece di
  `dominio.risorsa.azione`, permessi globali `*-global`, vincolo `minimum: 0` su `version` mancante.

- Una sessione Redis scritta da un'altra versione (classi rinominate, come `it.logicware.authz` → `com.logicwarez.authz`,
  o un altro `serialVersionUID` di `SessionContext`) faceva rispondere `500` a ogni richiesta dell'utente. Ora
  `authz-session` registra `springSessionDefaultRedisSerializer` (`TolerantSessionSerializer`): l'attributo
  illeggibile è ignorato e la sessione conta come assente (`401`, o un nuovo login su `/bff/login`). Si disattiva
  definendo un proprio bean con quel nome. Segnalato da Quadrava.

## [2.0.1] - 2026-10-31

### Corretto

- Con una sessione valida, un percorso inesistente rispondeva `401` invece di `404`, e una risposta asincrona (stream
  di eventi, `Callable`) su un percorso autenticato finiva in `401`: `SessionContextFilter` non girava negli error
  dispatch (verso `/error`) e negli async dispatch. Segnalato da Quadrava: il suo runtime legge ogni `401` come
  sessione scaduta e rifà il login in ciclo.

## [2.0.0] - 2026-10-31

Coordinate Maven `com.logicwarez.authz:authz-session|authz-rbac|authz-bff:2.0.0`, package Java
`com.logicwarez.authz.*`. Le pubblicazioni provvisorie dello stesso giorno (`com.enterprise.authz` 2.0.0 e
`it.logicware.authz` 3.0.0, stesso codice con un altro namespace) sono ritirate: non usarle.

Prima release delle librerie: ms-authz non è più un insieme di servizi (BFF gateway, auth-service, starter con
`X-Session-ID`) ma tre librerie Spring Boot 4.1 / Java 25 da incorporare in un'applicazione. Il codice a servizi
della 1.x è stato rimosso.

### Aggiunto

- `authz-session`: `SessionContext` in una sessione Spring Session Data Redis standard, `SessionContextConfigurer`
  per Spring Security, interfaccia `AuthorizationResolver`.
- `authz-rbac`: modello RBAC su PostgreSQL con history Flyway propria (`authz_schema_history`), risoluzione
  in-process al login, API di amministrazione `/api/v1/admin/**` con audit.
- `authz-bff`: login OIDC, logout sullo IAM, revoca delle sessioni, rate limiting del login, conforme ai contratti
  `bff.yaml` 0.3.0 e `authz.yaml` 0.1.0 di Quadrava (kit `npm run conformance:bff`: 13 su 13):
  - `GET /bff/login?return=<pagina>`: torna alla pagina dopo il login; accettata solo se la sua origine è
    un'applicazione (`authz.bff.frontend.allowed-origins` o l'origine pubblica del BFF), altrimenti `400` Problem;
    con una sessione già aperta torna subito indietro;
  - `GET /bff/user`: `username`, `name`, `email`, `roles`, `tenants` (`id`, `label`), `currentTenant`;
  - `POST /bff/tenant` `{"tenant": "<id>"}`: cambio di tenant della sessione (`204`, `404` se non offerto);
  - `POST /logout`: `200 {"redirect": "<logout sullo IAM>"}`;
  - `GET /authz/capabilities?app=` e `POST /authz/check` sui permessi della sessione;
  - header `X-Permissions-Version` su ogni risposta autenticata;
  - CSRF per applicazioni a pagina singola: cookie `XSRF-TOKEN` leggibile dalla pagina, header `X-XSRF-TOKEN`
    obbligatorio su `POST`, `PUT`, `PATCH`, `DELETE`.
- Migrazione `V3`: vincolo sul formato dei permessi, colonna `app_user.last_tenant_id`.
- Workflow CI e release (GitHub Packages, GitHub Release).

### Modificato (rispetto alla 1.x)

- **Permessi** nel formato `dominio.risorsa.azione`, minuscolo: `authz.rbac.manage`, `authz.rbac.manageglobal`,
  `authz.session.revoke`, `authz.session.revokeglobal` (prima `rbac:manage`, `rbac:manage-global`, ...). I permessi
  riservati a `GLOBAL_ADMIN` sono quelli la cui azione finisce in `global`. La `V3` rinomina quelli di sistema;
  quelli dell'applicazione vanno convertiti con una sua migrazione (il vincolo è `NOT VALID` sulle righe esistenti).
- **Tenant al login**: un utente con più tenant entra sull'ultimo usato (o sul primo), senza
  `tenant_selection_required`; il tenant si cambia con `POST /bff/tenant`. `?tenant=` su `/bff/login` resta come
  indicazione facoltativa.
- **Percorsi**: `/bff/session` → `/bff/user`, `/bff/logout` → `/logout`; `BffControllers.PUBLIC_PATHS` contiene
  solo `/bff/login`.
- **Controllo `Origin`**: ora affianca il token CSRF e rifiuta solo un'origine estranea (non più l'header assente).
- `AuthorizationResolver.Resolved` e `SessionContext` hanno i campi `tenants` (e `SessionContext` anche `name`);
  `Resolved` mantiene un costruttore senza tenant.

### Corretto

- Revoca delle sessioni sempre `501` con Boot 4: la configurazione dell'esempio usava `spring.session.redis.*`,
  ignorate da Boot 4; ora `spring.session.data.redis.*` (`repository-type: indexed`, `namespace`).
