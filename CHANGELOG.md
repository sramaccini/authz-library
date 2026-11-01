# Changelog

Formato [Keep a Changelog](https://keepachangelog.com/it/1.1.0/), versioni [Semantic Versioning](https://semver.org/lang/it/).

## [Non rilasciato]

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
