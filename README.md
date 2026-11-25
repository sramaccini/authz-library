# ms-authz — librerie BFF + autorizzazioni

Librerie **Spring Boot 4.1 / Java 25** da incorporare in un'applicazione (per esempio un monolite modulare) per
avere login OIDC con il pattern BFF, sessione su Redis e RBAC per tenant. Conformi ai contratti `bff.yaml` e
`authz.yaml` di **Quadrava**, quindi utilizzabili come back end di un front end Quadrava.

| Modulo | Contenuto |
|---|---|
| `authz-session` | `SessionContext` salvato in una sessione **Spring Session Data Redis** standard; filtro e `SessionContextConfigurer` per Spring Security; interfaccia `AuthorizationResolver` |
| `authz-rbac` | Modello RBAC su PostgreSQL, risoluzione in-process al login, API `/api/v1/admin/**`, migrazioni Flyway con history propria (`authz_schema_history`) |
| `authz-bff` | Login OIDC, `/bff/login`, `/bff/user`, `/bff/tenant`, `/bff/role`, `/logout`, `/authz/capabilities`, `/authz/check`, revoca `/bff/admin/users/{username}/sessions`, CSRF, controllo `Origin`, rate limiting del login |
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
        <version>2.6.0</version>
    </dependency>
    <dependency>
        <groupId>com.logicwarez.authz</groupId>
        <artifactId>authz-rbac</artifactId>  <!-- facoltativo: RBAC su PostgreSQL -->
        <version>2.6.0</version>
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
| `GET /bff/user` | `{username, name, email, roles, tenants: [{id, label}], currentTenant, operationalRoles: [{id, label}], currentRole}`; i campi dei tenant e dei ruoli operativi solo se l'utente ne ha; `401` senza sessione |
| `POST /bff/tenant` `{"tenant": "<id>"}` | `204`; `404` Problem se il tenant non è offerto all'utente; `400` se manca |
| `POST /bff/role` `{"role": "<id>"}` | `204` con la nuova `X-Permissions-Version`; `404` Problem se il ruolo non è uno dei ruoli operativi dell'utente; `400` se il corpo non è esattamente quello |
| `POST /logout` | `200 {"redirect": "<logout sullo IAM>"}`: la pagina naviga lì per chiudere anche l'SSO |
| `GET /authz/capabilities?app=<app>` | `{permissions, version}` e header `X-Permissions-Version`; `400` senza `app` |
| `POST /authz/check` `{"checks": [{permission, resource?}]}` | `{results: [{permission, resource?, allowed}]}`; massimo 200 controlli |

Regole di ogni chiamata:

- **Sessione assente o scaduta**: `401`, mai redirect.
- **CSRF**: cookie `XSRF-TOKEN` (non `HttpOnly`) già nella prima risposta; ogni `POST`, `PUT`, `PATCH`, `DELETE`
  deve rimandarlo nell'header `X-XSRF-TOKEN`, altrimenti `403`. In più, un header `Origin` presente ma estraneo
  alle applicazioni dà `403`.
- **`X-Permissions-Version`** su ogni risposta autenticata: cambia quando cambiano i permessi della sessione
  (per esempio dopo un cambio di tenant o di ruolo operativo).
- **Permessi** nel formato `dominio.risorsa.azione`, minuscolo (`tracker.issue.edit`). Lo schema RBAC lo impone
  con un vincolo (`ck_permission_code_format`); i permessi che finiscono in `global` sono riservati al ruolo di
  sistema `GLOBAL_ADMIN`.
- **Tenant**: al login l'utente entra sull'ultimo tenant usato (`app_user.last_tenant_id`), altrimenti sul primo
  in ordine di codice; non viene mai chiesto. L'etichetta mostrata è la descrizione del tenant (`tenant.description`).
- **Ruoli operativi** (parte facoltativa di `bff.yaml` 0.6.0, ADR-28 di Quadrava): per la separazione dei compiti
  l'utente lavora con un ruolo alla volta. Un ruolo con `app_role.is_base = TRUE` (il valore predefinito: tutti i ruoli
  esistenti) vale sempre; quelli con `FALSE` sono operativi e se ne attiva uno solo. I permessi della sessione sono
  quelli dei ruoli di base più quello attivo; senza ruoli operativi, quelli di tutti i ruoli, come prima. Al login
  l'utente entra sull'ultimo ruolo usato (`app_user.last_role_code`), altrimenti sul primo in ordine di codice; non
  viene mai chiesto. Si cambia con `POST /bff/role`, e il cambio di tenant tiene il ruolo se l'utente lo ha anche lì.
  L'etichetta è la descrizione del ruolo. Un `role` mandato dalla pagina a `/authz/*` è ignorato. Le richieste con
  un token non hanno un ruolo attivo: hanno i permessi di tutti i ruoli.
- **`X-Active-Role`**: per l'applicazione l'header è il ruolo attivo della sessione, mai quello mandato dalla pagina
  (assente senza ruolo e per le richieste con un token). Con il token relay va inoltrato ai servizi insieme al token,
  perché quelli che applicano la separazione dei compiti autorizzano con i ruoli di base più quel ruolo.
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

### Pseudonimizzazione di un utente (GDPR, ASVS 8.3.2)

`POST /api/v1/admin/tenants/{tenant}/users/{username}/forget` con `{"pseudonym": "..."}`, o da codice
`RbacAdminService.forgetUser(actor, tenant, username, pseudonym)`. Le regole sono quelle di `replaceUserRoles`
(tenant dell'amministratore, mai se stessi), e l'utente non deve avere più ruoli sul tenant. Si tolgono prima con
`replaceUserRoles` e una lista vuota, nella stessa transazione. Cosa fa:

- Nelle voci di `rbac_audit` del tenant il nome diventa lo pseudonimo, sia in autore e oggetto sia in ogni valore
  JSON uguale al nome (anche dentro liste e oggetti).
- Se l'utente non ha più ruoli su nessun tenant, la riga `app_user` viene eliminata insieme ai token personali, e il
  nome sparisce anche dalle voci senza tenant (token, attivazione). Un amministratore delegato non elimina un utente
  che il globale ha disattivato: la riga resta e la risposta ha `userDeleted: false`.
- Scrive una voce `USER_FORGOTTEN` che nomina solo lo pseudonimo.

La risposta è `{"pseudonym", "tenant", "auditEntries", "userDeleted"}`. La chiamata si può ripetere: con l'utente
già eliminato aggiorna solo l'audit del tenant. `findUser(actor, username)` restituisce un `Optional` e non lancia
eccezioni, quindi dentro la transazione del chiamante non la segna rollback-only.

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

`GET /bff/admin/users/{username}/sessions` le elenca, con gli stessi permessi e lo stesso filtro sul tenant
(stesso formato di `GET /bff/sessions`, `current` sempre `false`).

### Sessioni dell'utente

L'utente collegato vede e chiude le proprie sessioni (con il cookie di sessione; le scritture vogliono
`X-XSRF-TOKEN`). Serve `repository-type: indexed`, altrimenti `501`.

| Chiamata | Risposta |
|---|---|
| `GET /bff/sessions` | `[{id, createdAt, lastAccessedAt, ipAddress, userAgent, tenant, current}]`, ultimo accesso più recente prima |
| `DELETE /bff/sessions/{id}` | `204`; anche la sessione corrente (come un logout senza uscire dallo IAM); `404` se non è dell'utente |
| `DELETE /bff/sessions` | `204`: chiude tutte le sessioni dell'utente tranne quella della richiesta |

`id` è un hash dell'identificativo della sessione: non è il valore del cookie e non permette di usarla.
IP (dietro un proxy, con `server.forward-headers-strategy`) e user agent sono quelli del login; le sessioni
aperte prima della 2.3.0 li hanno vuoti.

### Back-channel logout (OIDC)

```yaml
authz.bff.backchannel-logout.enabled: true   # serve Redis con repository-type: indexed
```

Lo IAM chiama `POST /bff/backchannel-logout` (`logout_token` in un form, senza cookie né CSRF; è in
`BffControllers.PUBLIC_PATHS`) quando una sua sessione finisce, e il BFF chiude le sessioni collegate: quelle con
lo stesso `sid`, o tutte quelle del `sub` se il token non ha `sid`. Il logout token è verificato con le chiavi
(`jwk-set-uri`), l'emittente e il client della registrazione OIDC del login: firma, `aud`, scadenza, evento
`http://schemas.openid.net/event/backchannel-logout`, `jti` usato una volta sola, niente `nonce`. Risposte: `200`;
`400 {"error": "invalid_request"}` per un token non valido.

Keycloak, client del BFF (nel realm di sviluppo `keycloak/import/enterprise-realm.json` è già così, per l'app
demo su `8080`):

- *Backchannel logout URL*: `https://<bff>/bff/backchannel-logout` (raggiungibile da Keycloak: da un container
  verso l'host, `host.docker.internal`);
- *Backchannel logout session required*: on (mette `sid` nei token: si chiude solo la sessione uscita);
- *Front channel logout*: off.

Con questa configurazione chiudono anche le sessioni del BFF: il logout da un'altra applicazione del realm,
*Sign out* di un utente o di una sessione nella console di amministrazione, *Sign out all devices* nell'account
console e il cambio della password con *Sign out from other devices* (azione richiesta *Update Password*).
Per chiudere tutto a ogni cambio di password senza lasciare la scelta all'utente, un listener di eventi di
Keycloak (`UPDATE_PASSWORD`) che chiude le sessioni dell'utente.

## Funzioni facoltative

Tutte spente se non configurate.

### Permessi dell'applicazione

Un bean `PermissionContributor` aggiunge permessi che l'RBAC non conosce (per esempio i ruoli di un progetto) e può
decidere i controlli su una risorsa:

```java
@Bean
PermissionContributor projectRoles(ProjectMembers members) {
    return new PermissionContributor() {
        public Collection<String> permissions(SessionContext s) { return members.permissionsOf(s.username()); }
        public Optional<Boolean> check(SessionContext s, String permission, Resource r) {
            return r.type().equals("project") ? Optional.of(members.allows(s.username(), r.id(), permission))
                                              : Optional.empty();   // decide l'insieme dei permessi
        }
    };
}
```

`/authz/capabilities`, `/authz/check` e `X-Permissions-Version` usano l'insieme effettivo (sessione + contributor).
`@PreAuthorize` vede solo i permessi della sessione: nei servizi si usa `EffectivePermissions`.

### Login recente prima delle azioni sensibili

```yaml
authz.bff.recent-login:
  max-age: 15m
  paths:                       # spento con l'elenco vuoto; il metodo davanti è facoltativo
    - /api/v1/admin/**
    - /api/admin/**
    - POST /api/me/tokens
```

Sui percorsi indicati, una sessione autenticata sullo IAM da più di `max-age` riceve `401` con il Problem
`{"type": "urn:problem:authz:recent-login-required", "title": "Recent login required", "status": 401,
"maxAge": 900}`; la sessione resta valida per il resto. La pagina rimanda allora a
`/bff/login?return=<pagina>&max_age=<secondi>` (anche con la sessione aperta si passa dallo IAM): lo IAM chiede di
nuovo le credenziali se la sua autenticazione è più vecchia (`max_age=0`: sempre) e al ritorno la sessione ha il
nuovo momento dell'autenticazione. Il momento è il claim `auth_time` dell'ID token (il login, se manca); le sessioni
aperte prima della 2.4.0 non lo hanno e contano come vecchie. Vale per le sessioni del browser: le richieste con un
token non sono controllate.

### Limite di frequenza delle sessioni

```yaml
authz.bff.session-rate-limit:
  enabled: true
  # paths: ["/api/**"]   max-requests: 600   window: 1m   redis-key-prefix: "authz:ratelimit:session:"
```

Limite per utente (tutte le sue sessioni insieme) sulle richieste delle sessioni del browser, contato su Redis:
oltre il massimo `429` con `Retry-After`. `/bff/**` resta fuori; le richieste con un token hanno il loro limite
(`authz.bff.bearer.rate-limit`). Senza Redis, o con Redis non raggiungibile, non limita.

### Token relay verso servizi separati

```yaml
authz.bff.token-relay:
  enabled: true
  # clock-skew: 60s      # rinnova l'access token che scade entro questo tempo
```

Di norma il BFF elimina access e refresh token subito dopo il login. Con il relay li lascia nella sessione (Redis),
per inoltrare le richieste a servizi separati che verificano il token dell'utente:

```java
// in un filtro o controller dell'applicazione, dopo la catena di sicurezza
Optional<String> token = sessionAccessTokens.forRequest(request, response);
if (token.isEmpty()) { response.setStatus(401); return; }
forwarded.header("Authorization", "Bearer " + token.get());
```

- Il token scaduto (o in scadenza) si rinnova con il refresh token e il nuovo viene salvato nella sessione.
- Vuoto senza una sessione del browser (anche per le richieste con un token), per le sessioni aperte prima di
  attivare il relay e quando il rinnovo fallisce: refresh token scaduto o revocato → il client viene tolto e serve
  un nuovo login; IAM non raggiungibile → il client resta e un tentativo successivo può riuscire.
- I token finiscono con la sessione: logout, revoca, back-channel logout, scadenza.
- La sessione su Redis contiene i token: Redis va protetto (rete privata, autenticazione, TLS) come un archivio di
  credenziali. Con la rotazione dei refresh token di Keycloak (*Revoke Refresh Token* attivo) due rinnovi
  contemporanei della stessa sessione possono far fallire il secondo: meglio lasciarla spenta (predefinito) o
  ammettere un riuso (*Refresh Token Max Reuse*).
- Inoltrando la risposta di un servizio, non copiarne l'header `X-Permissions-Version`: lo imposta il BFF sulla
  sessione del front end e quello del servizio lo sovrascriverebbe.

### Schema dedicato

`authz.rbac.schema: authz` — tabelle e history delle migrazioni nello schema `authz` (creato se manca), query della
libreria qualificate; utile quando l'applicazione ha le sue migrazioni Flyway nello schema `public`.

### Accesso con token (script, CI, service account)

```yaml
authz.bff.bearer:
  enabled: true
  paths: ["/api/**"]          # solo qui il bearer è accettato
  allowed-clients: [cli-tools] # claim azp ammessi; vuoto = tutti i client del realm
  # issuer-uri: ...            # predefinito: issuer della registrazione OIDC
  # tenant-header: X-Tenant
  # rate-limit: {max-requests: 600, window: 1m}
```

Il token è un access token dello IAM (`preferred_username` deve esistere come utente RBAC attivo; per un service
account di Keycloak è `service-account-<client>`) o un token personale `pat_…`. Il tenant viene da `X-Tenant`,
altrimenti è l'ultimo usato dall'utente. Nessuna sessione, niente CSRF; cookie e token insieme danno `400`.
Esiti: `401` token non valido o scaduto, `403` utente o tenant non autorizzato, `429` oltre il limite per utente
(contato su Redis; senza Redis il limite non si applica). Nel codice l'`Authentication` è un `TokenAuthentication`.

### Directory del tenant

`TenantDirectory` (bean di `authz-rbac`) cerca gli utenti attivi con un ruolo sul tenant, per selettori e menzioni.
Con `authz.rbac.directory.permission: tracker.user.read` c'è anche `GET /api/v1/directory/users?q=mar&limit=20`
→ `[{username, email}]` sul tenant della sessione (`403` senza il permesso).

### Token di accesso personali

`authz.rbac.tokens.enabled: true` (`max-per-user: 20`, `max-days: 366`):

| Chiamata | Risposta |
|---|---|
| `GET /api/v1/tokens` | token non revocati dell'utente: `{id, name, hint, createdAt, expiresAt, lastUsedAt}` |
| `POST /api/v1/tokens` `{"name": "CI", "expiresInDays": 90}` | `201` con `token` in chiaro, l'unica volta; `409` oltre il massimo |
| `DELETE /api/v1/tokens/{id}` | `204`; `404` se non è un token dell'utente |

Si gestiscono solo da una sessione del browser (`403` con un token). Nel database c'è solo lo SHA-256.

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
IAM_CLIENT_SECRET="$BFF_CLIENT_SECRET" java -jar examples/authz-demo-app/target/authz-demo-app-2.6.0.jar --spring.profiles.active=dev
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

## Licenza

[Mozilla Public License 2.0](LICENSE).
