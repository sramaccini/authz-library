# ms-authz — librerie BFF + autorizzazioni

Librerie **Spring Boot 4.1 / Java 25** da incorporare in un'applicazione (per esempio un monolite modulare) per
avere login OIDC con il pattern BFF, sessione su Redis e RBAC per tenant. Conformi ai contratti `bff.yaml` e
`authz.yaml` di **Quadrava**, quindi utilizzabili come back end di un front end Quadrava.

| Modulo | Contenuto |
|---|---|
| `authz-session` | `SessionContext` salvato in una sessione **Spring Session Data Redis** standard; filtro e `SessionContextConfigurer` per Spring Security; interfaccia `AuthorizationResolver` |
| `authz-rbac` | Modello RBAC su PostgreSQL, risoluzione in-process al login, API `/api/v1/admin/**`, migrazioni Flyway con history propria (`authz_schema_history`) |
| `authz-bff` | Login OIDC, `/bff/login`, `/bff/user`, `/bff/tenant`, `/logout`, `/authz/capabilities`, `/authz/check`, revoca `/bff/admin/users/{username}/sessions`, CSRF, controllo `Origin`, rate limiting del login |
| `examples/authz-demo-app` | Un solo deployable che assembla le tre librerie (non pubblicato) |

Novità e modifiche per versione: [CHANGELOG.md](CHANGELOG.md).

## Uso in un'applicazione

Le release sono pubblicate su **GitHub Packages**. Maven richiede un token anche per i pacchetti pubblici: un
personal access token (classic) con `read:packages` in `~/.m2/settings.xml`:

```xml
<servers>
    <server>
        <id>github-authz</id>
        <username>UTENTE_GITHUB</username>
        <password>TOKEN_CON_READ_PACKAGES</password>
    </server>
</servers>
```

Nel `pom.xml` dell'applicazione:

```xml
<repositories>
    <repository>
        <id>github-authz</id>
        <url>https://maven.pkg.github.com/sramaccini/authz-library</url>
    </repository>
</repositories>

<dependencies>
    <dependency>
        <groupId>com.logicwarez.authz</groupId>
        <artifactId>authz-bff</artifactId>   <!-- porta con se' authz-session -->
        <version>2.1.0</version>
    </dependency>
    <dependency>
        <groupId>com.logicwarez.authz</groupId>
        <artifactId>authz-rbac</artifactId>  <!-- facoltativo: RBAC su PostgreSQL -->
        <version>2.1.0</version>
    </dependency>
</dependencies>
```

Le librerie sono compilate contro Spring Boot 4.1.2: l'applicazione deve usare la stessa linea 4.1.x.
In GitHub Actions basta `secrets.GITHUB_TOKEN` (con `permissions: packages: read`) come password del server.

Sicurezza:

```java
http.with(BffConfigurer.bff(), Customizer.withDefaults())
    .authorizeHttpRequests(auth -> RbacAdminSecurity.adminApi(auth
            .requestMatchers(BffControllers.PUBLIC_PATHS).permitAll())
        .anyRequest().authenticated());
// nelle API: @PreAuthorize("hasAuthority('tracker.issue.edit')"), @AuthenticationPrincipal SessionContext session
```

Configurazione completa in [examples/authz-demo-app/src/main/resources/application.yml](examples/authz-demo-app/src/main/resources/application.yml).
Proprietà da non dimenticare:

- `spring.session.data.redis.repository-type: indexed` — senza, la revoca delle sessioni risponde `501`
  (in Boot 4 le vecchie `spring.session.redis.*` sono ignorate);
- `authz.bff.frontend.*` — home, pagina di errore del login, ritorno dopo il logout, origini delle applicazioni;
- `server.forward-headers-strategy: framework` — **solo dietro un proxy fidato**, vedi sotto;
- `spring.mvc.async.request-timeout: -1` — se l'applicazione apre stream di eventi, vedi sotto.

Un'applicazione senza `authz-rbac` fornisce un proprio bean `AuthorizationResolver`.

## Contratto con il front end (Quadrava `bff.yaml` 0.3.0, `authz.yaml` 0.1.0)

Verificato con il kit di Quadrava, 13 controlli su 13, anche con un login reale su Keycloak:

```bash
npm run conformance:bff -- --bff http://localhost:8080 --return http://localhost:4200/ --cookie "SESSION_ID=..."
```

| Chiamata | Risposta |
|---|---|
| `GET /bff/login?return=<pagina>[&tenant=<id>]` | `302` allo IAM, poi alla pagina. `return` deve avere un'origine delle applicazioni (`authz.bff.frontend.allowed-origins` o l'origine pubblica del BFF), altrimenti `400` Problem. Con una sessione già aperta: `302` subito alla pagina |
| `GET /bff/user` | `{username, name, email, roles, tenants: [{id, label}], currentTenant}`; `401` senza sessione |
| `POST /bff/tenant` `{"tenant": "<id>"}` | `204`; `404` Problem se il tenant non è offerto all'utente; `400` se manca |
| `POST /logout` | `200 {"redirect": "<logout sullo IAM>"}`: la pagina naviga lì per chiudere anche l'SSO |
| `GET /authz/capabilities?app=<app>` | `{permissions, version}` e header `X-Permissions-Version`; `400` senza `app` |
| `POST /authz/check` `{"checks": [{permission, resource?}]}` | `{results: [{permission, resource?, allowed}]}`; massimo 200 controlli |

Regole di ogni chiamata:

- **Sessione assente o scaduta**: `401`, mai redirect.
- **CSRF**: cookie `XSRF-TOKEN` (non `HttpOnly`) già nella prima risposta; ogni `POST`, `PUT`, `PATCH`, `DELETE`
  deve rimandarlo nell'header `X-XSRF-TOKEN`, altrimenti `403`. In più, un header `Origin` presente ma estraneo
  alle applicazioni dà `403`.
- **`X-Permissions-Version`** su ogni risposta autenticata: cambia quando cambiano i permessi della sessione
  (per esempio dopo un cambio di tenant).
- **Permessi** nel formato `dominio.risorsa.azione`, minuscolo (`tracker.issue.edit`). Lo schema RBAC lo impone
  con un vincolo (`ck_permission_code_format`); i permessi che finiscono in `global` sono riservati al ruolo di
  sistema `GLOBAL_ADMIN`.
- **Tenant**: al login l'utente entra sull'ultimo tenant usato (`app_user.last_tenant_id`), altrimenti sul primo
  in ordine di codice; non viene mai chiesto. L'etichetta mostrata è la descrizione del tenant (`tenant.description`).
- **Stream di eventi** (data source `live` di Quadrava): con BFF e API nello stesso processo non c'è un proxy da
  configurare. L'API risponde `text/event-stream` (per esempio `SseEmitter` con timeout `0`) e
  `spring.mvc.async.request-timeout: -1` toglie il limite di durata; davanti, nessun proxy deve fare buffering.
- **Dietro un proxy** (per esempio l'immagine runtime di Quadrava con `QUADRAVA_BFF_URL`):
  `server.forward-headers-strategy: framework` fa usare `X-Forwarded-Host` e `X-Forwarded-Proto` al callback del
  login (`{baseUrl}`) e alla verifica di `return`. Va attivato solo se il proxy è fidato e sovrascrive quegli
  header: altrimenti un client potrebbe falsificarli (anche l'IP del rate limiting viene da `X-Forwarded-For`).

Errori del login → redirect a `authz.bff.frontend.login-failure-url?error=access_denied|auth_service_unavailable|login_failed`
(`tenant_selection_required` solo con un `AuthorizationResolver` applicativo che lo richiede).

## Amministrazione di ruoli e permessi

API `/api/v1/admin/**` di `authz-rbac`, descritta in [docs/authz-admin-openapi-spec.json](docs/authz-admin-openapi-spec.json).
Tutte le chiamate passano dal BFF con il cookie di sessione; le scritture vogliono l'header `X-XSRF-TOKEN`.

La definizione è generata da springdoc sul controller e verificata dal build (`AdminOpenApiTest`): se il controller
cambia e il file no, `mvn verify` fallisce. Per rigenerarla:

```bash
mvn -pl authz-rbac -am test -Dtest=AdminOpenApiTest -Dsurefire.failIfNoSpecifiedTests=false -Dopenapi.update=true
```

springdoc è solo una dipendenza di test: le applicazioni che vogliono anche `/v3/api-docs` lo aggiungono loro.

| Chi | Permesso | Può |
|---|---|---|
| Amministratore delegato (`TENANT_ADMIN`) | `authz.rbac.manage`, `authz.session.revoke` | censire utenti, assegnare/togliere ruoli e revocare sessioni **solo nel tenant della propria sessione**, leggere l'audit del proprio tenant |
| Amministratore globale (`GLOBAL_ADMIN`) | `authz.rbac.manageglobal`, `authz.session.revokeglobal` (+ i precedenti) | tutto su tutti i tenant, più definire ruoli, creare tenant, attivare/disattivare utenti |

- Il catalogo dei permessi e i ruoli di sistema si modificano solo con le migrazioni Flyway.
- Nessuno può modificare la propria utenza; i ruoli con permessi `...global` li gestisce solo il globale.
- Le modifiche valgono **dal login successivo** dell'utente (o dal cambio di tenant). Per un effetto immediato:
  `DELETE /bff/admin/users/{username}/sessions`.
- Ogni modifica è registrata in `rbac_audit` (chi, quando, stato prima e dopo).
- Primo amministratore globale in produzione: SQL una tantum, commento in fondo a `V2__rbac_administration.sql`.

### Revoca delle sessioni

`DELETE /bff/admin/users/{username}/sessions` chiude subito le sessioni di un utente: con `authz.session.revoke`
solo quelle aperte sul tenant dell'amministratore, con `authz.session.revokeglobal` tutte.

| Esito | Significato |
|---|---|
| `200` | `{"username": "...", "tenant_id": "TENANT_A" \| null, "revoked_sessions": 2}`; `tenant_id` è `null` per la revoca globale |
| `400` | `username` non valido (`^[A-Za-z0-9._@-]{1,150}$`) |
| `401` | sessione dell'amministratore assente o scaduta |
| `403` | permesso mancante, token CSRF mancante o `Origin` estranea |
| `501` | Spring Session non configurato con `repository-type: indexed` |

## Sviluppo e avvio locale

```bash
cp .env.example .env   # poi sostituire i segnaposto
docker compose up -d   # PostgreSQL 17, Redis 7.4, Keycloak 26 (realm "enterprise" importato)
mvn install            # build e test di librerie ed esempio
```

I test di integrazione avviano con Testcontainers un PostgreSQL 17 (`RbacPostgresTest`: migrazioni, risoluzione al
login, regole dell'amministrazione, audit) e un Redis 7.4 (`BffRedisTest`: sessione indicizzata, revoca, sessioni
di un'altra versione). Richiedono Docker in esecuzione; senza Docker vengono saltati e gli altri test girano lo stesso.

```bash
set -a; . ./.env; set +a
IAM_CLIENT_SECRET="$BFF_CLIENT_SECRET" java -jar examples/authz-demo-app/target/authz-demo-app-2.1.0.jar --spring.profiles.active=dev
```

Utenti demo (password `DEMO_USER_PASSWORD` di `.env`): `mario.rossi` (TENANT_A), `anna.bianchi` (TENANT_A e
TENANT_B), `admin.tenant.a` (amministratore delegato di TENANT_A), `admin.globale` (amministratore globale).
L'import del realm usa `OVERWRITE_EXISTING`: le modifiche fatte a mano dalla console di Keycloak si perdono al
riavvio del container. Il client `bff-gateway` accetta il ritorno dal login su `http://localhost:8080` (app demo) e
`http://localhost:8090` (immagine runtime di Quadrava davanti al BFF); dopo una modifica del realm il container di
Keycloak va riavviato.

Variabili principali: `IAM_ISSUER_URI`, `IAM_CLIENT_ID`, `IAM_CLIENT_SECRET`, `AUTH_DB_URL`, `AUTH_DB_USER`,
`AUTH_DB_PASSWORD`, `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `FRONTEND_URL`, `FORWARD_HEADERS_STRATEGY`.

**Windows**: se l'avvio fallisce con `Unable to establish loopback connection` (selector NIO), la cartella temp ha
un percorso in formato corto 8.3 dove il JDK non riesce a creare il socket AF_UNIX: avviare con
`-Djdk.net.unixdomain.tmpdir=C:\tmp\ud` (cartella esistente) e, per i test,
`JAVA_TOOL_OPTIONS=-Djdk.net.unixdomain.tmpdir=C:\tmp\ud`.

## Release

1. Versione nei pom (`mvn versions:set -DnewVersion=X.Y.Z -DgenerateBackupPoms=false`) e sezione `## [X.Y.Z]`
   nel CHANGELOG, in un commit su `master`.
2. `git tag vX.Y.Z && git push origin master vX.Y.Z`.
3. Il workflow [release.yml](.github/workflows/release.yml) verifica che il tag corrisponda ai pom, esegue i test,
   pubblica le librerie su GitHub Packages e crea la GitHub Release con le note del CHANGELOG e i jar.
4. Riportare `master` alla versione successiva `-SNAPSHOT`.

## Scelte da validare prima della produzione

- **Audit RBAC**: definire conservazione e accesso al registro `rbac_audit` (GDPR).
- **Logout IAM**: il post logout redirect URI va registrato sul client dello IAM. Il logout avviato altrove
  (un'altra applicazione, la console dello IAM) non chiude le sessioni del BFF: serve il back-channel logout (non
  incluso).
- **Serializzazione JDK** degli attributi di sessione (`TolerantSessionSerializer`): un aggiornamento che cambia le
  classi in sessione chiude le sessioni aperte, senza errori (l'attributo illeggibile è ignorato e l'utente rifà il
  login).
