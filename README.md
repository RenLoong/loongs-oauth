# loongs/oauth

OAuth 2.1 authorization server and resource server for the loong-swoole stack (PHP 8.4, Swoole
coroutines), following **draft-ietf-oauth-v2-1** and the RFCs it builds on. The core is
framework-neutral and storage-agnostic (`OAuthRequest` in, `OAuthResponse` out, six repository
interfaces). Adapters: **loongs/orm** (MySQL, one set of tables per tenant), **loongs/cache** (Redis
codes / tokens), memory (tests), and **loongs/framework** (routes + bearer middleware).

```bash
composer require loongs/oauth:dev-main      # Packagist; locally via a path repo (see "Development")
```

## Layout

```
src/
  AuthorizationServer.php     authorize (code + PKCE), token (authorization_code | refresh_token | client_credentials | registerGrant() extensions),
                              revoke (RFC 7009), introspect (RFC 7662), metadata (RFC 8414), jwks
  ResourceServer.php          bearer extraction (header / form body, never query), opaque + JWE validation, WWW-Authenticate
  ServerConfig.php            issuer, scopes, TTLs, token format (opaque | jwe), signing + encryption keys, policy switches
  Pkce.php TokenInfo.php
  Authorization/              AuthorizationRequest, AuthorizationDecision, AuthorizationHandlerInterface (host login + consent),
                              CallableAuthorizationHandler
  Grant/                      ExtensionGrantHandler, ExtensionGrantResult (RFC 6749 §4.5 extension grants)
  Entity/                     Client, AuthorizationCode, AccessToken, RefreshToken, Consent (readonly)
  Storage/                    ClientRepositoryInterface AuthCodeRepositoryInterface AccessTokenRepositoryInterface
                              RefreshTokenRepositoryInterface TokenFamilyRepositoryInterface ConsentRepositoryInterface
                              PurgeableInterface StorageInterface Stores
                              MemoryStorage · OrmStorage (loongs/orm) · CacheTokenStorage (loongs/cache)
  Jwt/                        Jwt (compact JWS), SigningKey (RS256 / ES256, RFC 7638 kid), JwkSet (JWKS ⇄ PEM), Der,
                              Jwe (RFC 7516 compact, RSA-OAEP-256 | dir + A256GCM), EncryptionKey, Oaep, JwtException
  Console/InstallCommand.php  ./loongs oauth:install [connection] (DDL from the connection config)
  Http/                       OAuthRequest, OAuthResponse
  Framework/                  Bridge, OAuthRoutes, BearerMiddleware (loongs/framework)
  Exception/                  OAuthException (RFC 6749 §5.2 / RFC 6750 §3), RedirectableException
  Support/                    Crypto (CSPRNG, hashing, constant-time), Scope
tests/extension_grant_test.php  dependency-free tests of extension grants
```

## Quick start

```php
use Loongs\OAuth\AuthorizationServer;
use Loongs\OAuth\Authorization\AuthorizationDecision;
use Loongs\OAuth\Entity\Client;
use Loongs\OAuth\Http\OAuthRequest;
use Loongs\OAuth\ServerConfig;
use Loongs\OAuth\Storage\OrmStorage;
use Loongs\OAuth\Storage\Stores;

$storage = new OrmStorage($tenantConnection);        // or new OrmStorage() inside Orm::tenant(), or MemoryStorage
$storage->install();                                 // CREATE TABLE IF NOT EXISTS, DDL from the connection's config
$server = new AuthorizationServer(new ServerConfig(issuer: 'https://auth.example.com', scopes: ['read', 'write'], defaultScopes: ['read']),
    Stores::of($storage));

$storage->saveClient(Client::public('spa', 'SPA', ['https://app.example.com/cb'], ['read', 'write']));
[$svc, $secret] = Client::confidential('billing', 'Billing', [], ['client_credentials'], ['read']);   // secret shown once
$storage->saveClient($svc);

// authorization endpoint: the host decides how the user logs in and consents
$response = $server->authorize(OAuthRequest::fromGlobals(), function ($authRequest, $request, $server) {
    $user = current_user_id();                        // your session / SSO
    return $user === null
        ? AuthorizationDecision::respond(render_login_page($authRequest->parameters()))
        : AuthorizationDecision::approve($user, remember: true);
});
$server->token($request);       $server->revoke($request);      $server->introspect($request);
$server->metadata();            $server->jwks();

$info = $server->resourceServer()->authenticate($request, ['read']);   // TokenInfo, or OAuthException (400/401/403 + WWW-Authenticate)
```

loongs/framework: `OAuthRoutes::register($router, $server, $handler)` mounts every endpoint (paths from
`ServerConfig::endpoint()`, metadata at `/.well-known/oauth-authorization-server{issuer path}`), and
`BearerMiddleware::for($resourceServer, 'scope', …)` protects routes (or subclass it with
`protected array $scopes` and register `BearerMiddleware::resolveUsing()` for container-built use).
On success the request carries `oauth` (TokenInfo), `oauth_user_id`, `oauth_client_id`, `oauth_scopes`.

## Grants and token lifecycle

| | |
|---|---|
| `authorization_code` | PKCE required for every client (`requirePkce`), `S256` only (`allowPlainPkce` = false; a missing method defaults to plain and is rejected). Codes: 256-bit, stored hashed, **single use**, 60 s TTL (max 600). Code bound to client, redirect URI and challenge. Failed PKCE / redirect checks do not burn the code. |
| `refresh_token` | Issued when the client is allowed the grant. **Rotated on every use** for public clients and, by default, confidential ones too (`rotateConfidentialRefreshTokens`). Replaying a rotated token revokes the whole family. Scope may be narrowed, never widened; the original grant scope is kept. |
| `client_credentials` | Confidential clients only; no refresh token; `sub` = client id. |
| removed | implicit (`response_type=token` → `unsupported_response_type`), password (`unsupported_grant_type`). |
| extension grants | RFC 6749 §4.5, opt-in: `registerGrant('urn:…', handler)`; only clients that list the grant URI may use it. See below. |

### Extension grants (RFC 6749 §4.5)

For first-party sign-in flows that are not an OAuth redirect — e.g. a WeChat mini program exchanging
a `wx.login()` code for tokens of an admin account that was **bound earlier** with a password login.
The server keeps doing everything security-relevant (client authentication, grant permission, scope
resolution, new token family, rotating refresh tokens, reuse detection); the handler only decides
*who* the tokens are for:

```php
use Loongs\OAuth\Grant\ExtensionGrantResult;

const WECHAT = 'urn:loongs:params:oauth:grant-type:wechat-mini';
$server->registerGrant(WECHAT, function (OAuthRequest $req, Client $client, AuthorizationServer $as): ExtensionGrantResult {
    $openid = $wechat->code2session((string) $req->param('code', 'post'));      // your code
    $adminId = $bindings->adminFor($openid)
        ?? throw OAuthException::invalidGrant('Not bound: sign in with username + password first.');
    return new ExtensionGrantResult((string) $adminId);    // scopes: request `scope` or defaults; refresh token: yes
});
Client::public('admin-mobile', 'Admin app', $redirects, ['admin', 'profile'], true, [WECHAT]);
```

- The grant type must be an absolute URI (a URN or URL) and not a built-in grant; `password` stays unsupported.
- Handler: `ExtensionGrantHandler` implementation or a Closure. Throw `OAuthException` (`invalid_request`,
  `invalid_grant`, …) to reject; the description reaches the client. A non-`ExtensionGrantResult` return is a `server_error`.
- `ExtensionGrantResult(userId, ?scopes, refreshToken = true, extra = [])`; `extra` adds members to the token
  response but can never override the standard ones. `grant_types_supported` in the metadata lists registered grants.
- Tests: `php tests/extension_grant_test.php` (no dependencies) and section A5 of `smoke_oauth.php`.

**Families.** A code and every token issued from it (across rotations) share a family id. A reused code,
a replayed refresh token or a revoked refresh token revokes the family: existing rows are marked, and a
family record makes validation reject tokens written *later* (e.g. by the winner of a concurrent double
exchange). Atomicity is one conditional `UPDATE … WHERE used_at IS NULL` (MySQL) or `SET NX` (Redis):
of N simultaneous exchanges of one code exactly one succeeds (smoke: 8 parallel requests, 4 workers).

## Tokens and secrets

- Every secret from `random_bytes()` (CSPRNG): codes / access / refresh tokens 32 bytes (base64url, 43 chars), ids 16 bytes.
- Stored as HMAC-SHA-256 (`tokenPepper`, default empty = plain SHA-256); raw values never touch storage or logs.
- Client secrets: `password_hash()` (Argon2id, bcrypt fallback); unknown clients verify a dummy hash (no timing oracle).
- Comparisons: `hash_equals` (PKCE) / `password_verify` (secrets).
- Access tokens are **opaque** by default. Self-contained tokens are always **encrypted** — there is no plaintext JWT mode
  (`accessTokenFormat: 'jwt'` is rejected):
  `accessTokenFormat: ServerConfig::FORMAT_JWE` = a nested JWT (RFC 7519 §5.2): an RFC 9068 JWS (`typ: at+jwt`, claims
  `iss exp aud sub client_id iat jti scope`, + `gty` for client_credentials; RS256 ≥2048-bit or ES256) encrypted as a compact
  JWE (RFC 7516) with header `{alg, enc: A256GCM, kid, typ: at+jwt, cty: JWT}`. Key management:
  - `EncryptionKey::generateRsa()` / `fromRsaPrivatePem()` / `fromRsaPublicPem()` → `RSA-OAEP-256` (OAEP SHA-256 / MGF1-SHA-256, implemented
    over openssl raw RSA with a constant-time decode; the AS may hold only the public key, resource servers the private key);
  - `EncryptionKey::direct($32bytes)` / `generateDirect()` → `dir` (shared symmetric key).
  All openssl, no JWT library; interop-checked against python `cryptography` and the `openssl pkeyutl` CLI.
- The resource server decrypts (key chosen by `kid` + `alg`), then verifies the inner JWS against the JWKS and the claims. Rejected:
  plain (unencrypted) JWS / JWT even with a valid signature, `alg: none`, any `alg` other than RSA-OAEP-256 / dir, any `enc` other than
  A256GCM, `zip` / `crit`, missing `cty: JWT`, inner `typ` ≠ `at+jwt`, tampered header / encrypted key / IV / ciphertext / tag, wrong or
  unknown keys (an undecryptable CEK continues with a random one, so every failure ends at the GCM tag, RFC 7516 §11.5).
- JWKS / metadata publish **public signing keys only** (`previousKeys` during rotation); encryption private keys and `dir` secrets are
  never published (`EncryptionKey` hides key material from `print_r` / `var_dump` and refuses `serialize`). `previousEncryptionKeys`
  keeps decrypting old tokens during an encryption-key rotation.
- **Revocation caveat:** JWE tokens are also stored by `jti`, so revocation and introspection work at the AS and at any resource server
  that shares the token store (`ResourceServer::fromServer()` / `$as->resourceServer()`). A resource server that only has the keys
  (no store) accepts a revoked token until `exp` — keep `accessTokenTtl` short or share the store.

## Multi-tenancy (loongs/orm)

`OrmStorage` resolves its connection on every statement, like every loongs/orm call:
`new OrmStorage($spec)` pins a tenant (name / array / DSN / ConnectionConfig), `new OrmStorage()` follows
the coroutine's `Orm::tenant()` scope, `->on($other)` rebinds. Give each tenant its own issuer
(`https://auth.example.com/{tenant}` → metadata at `/.well-known/oauth-authorization-server/{tenant}`).
A token, code or client secret of one tenant is unknown to the others (separate tables). Mixed storage:
`new Stores(clients: $orm, consents: $orm, codes: $cache, accessTokens: $cache, refreshTokens: $cache, families: $cache)`
with `CacheTokenStorage` on a per-tenant Redis prefix. `purgeExpired()` from a crontab process.

### Creating the tables (per database / tenant)

The DDL is generated from the target connection's config, not from a static file:

```php
OrmStorage::installOn('tenant_42');                      // named connection (config/database.php)
OrmStorage::installOn(['driver' => 'mysql', 'database' => 'tenant_42', /* … */ 'prefix' => 'app_',
    'engine' => 'InnoDB', 'charset' => 'utf8mb4', 'collation' => 'utf8mb4_unicode_ci']);   // tenant config array
OrmStorage::installOn('mysql://u:p@host/tenant_42?prefix=app_');
Orm::tenant($spec, fn () => (new OrmStorage())->install());   // inside a tenant scope
(new OrmStorage($spec))->schema();                       // dry run: table => CREATE TABLE IF NOT EXISTS …
```

```bash
./loongs oauth:install [connection|mysql://…] [--prefix=] [--tables=oauth_] [--engine=] [--charset=] [--collation=] [--dry-run]
# register once in server/config/console.php: 'commands' => [\Loongs\OAuth\Console\InstallCommand::class]
```

- Table name = connection `prefix` + `oauth_` + table (`app_oauth_clients`); the storage uses the same names for every query
  (`$storage->table('clients')`). `engine` (default InnoDB), `charset` (utf8mb4) and `collation` (default `<charset>_bin`) come from the
  same config. Whatever the table collation, identifiers (client_id, user_id) are `<charset>_bin` and hashes `ascii_bin`
  (case-sensitive lookups). Every value is validated as `[A-Za-z0-9_]` before it reaches DDL.
- Idempotent: `CREATE TABLE IF NOT EXISTS`; `install()` returns `table => created (true) | already existed (false)`. It does not alter
  existing tables. The database itself must exist.
- `prefix` / `engine` / `charset` / `collation` are read per call through loongs/orm's public API (`Orm::config($spec)`), so they are
  detected for named connections, arrays, URLs and inside `Orm::tenant()` scopes alike (`new OrmStorage()` in a scope with
  `prefix => 'app_'` uses `app_oauth_*`). An explicit prefix (`new OrmStorage($spec, 'x_')`, `--prefix=`) is an optional override.
  Requires loongs/orm with per-connection prefix support (dev-main).

## Spec compliance checklist

OAuth 2.1 = draft-ietf-oauth-v2-1 (latest draft at the time of writing); ✅ implemented and covered by `smoke_oauth.php`, ➖ not implemented (by choice / out of scope).

| Requirement | Source | Status |
|---|---|---|
| Authorization code grant; PKCE required; `S256`; `plain` rejected by default; verifier 43–128 unreserved chars | 2.1 §4.1, §7.5; RFC 7636 | ✅ |
| Code single use, short lifetime (60 s), bound to client + redirect URI; reuse → revoke tokens issued from it | 2.1 §4.1.2, §4.1.3 | ✅ |
| `code_verifier` without a challenge rejected; missing / wrong verifier → `invalid_grant` | 2.1 §4.1.3 | ✅ |
| Redirect URI: exact string match; no fragment; loopback IP any port | 2.1 §2.3.1, §8.4.2 | ✅ |
| Invalid client / redirect URI → no redirect; other errors redirected with `state` | 2.1 §4.1.2.1 | ✅ |
| `iss` in authorization responses (success and error) + metadata flag | RFC 9207 | ✅ |
| `state` passed through unchanged | 2.1 §4.1.1 | ✅ |
| Implicit and password grants removed | 2.1 §10 | ✅ |
| Client authentication: `client_secret_basic` (form-urlencoded id/secret), `client_secret_post`, `none`; one method per request; 401 + `WWW-Authenticate: Basic` | 2.1 §2.4 / RFC 6749 §2.3.1 | ✅ |
| Confidential vs public clients; `client_credentials` only for confidential | 2.1 §2.1, §4.2 | ✅ |
| Refresh tokens for public clients rotated, reuse revokes the family | 2.1 §4.3.1, RFC 9700 §4.14 | ✅ (sender-constraining ➖) |
| Refresh scope ⊆ original grant | 2.1 §4.3 | ✅ |
| Token response: `token_type` Bearer, `expires_in`, `scope`, `Cache-Control: no-store` | 2.1 §3.2.3 | ✅ |
| Error responses: JSON `error` / `error_description`, correct codes and statuses | 2.1 §3.2.4 / RFC 6749 §5.2 | ✅ |
| Repeated (array-style `name[]`) parameters rejected; token endpoint POST + form encoding only | 2.1 §3.1, §3.2 | ✅ (plain `a=1&a=2` duplicates: PHP keeps the last) |
| Bearer token only in `Authorization` header or form body; query string rejected | 2.1 §5.2 / RFC 6750 §2 | ✅ |
| Resource server errors with `WWW-Authenticate` (`invalid_request` 400, `invalid_token` 401, `insufficient_scope` 403 + `scope`; no error code when no token) | RFC 6750 §3 | ✅ |
| Token revocation; refresh-token revocation revokes the grant; 200 for unknown tokens; `unsupported_token_type` | RFC 7009 | ✅ |
| Token introspection, authenticated callers, `active:false` otherwise | RFC 7662 | ✅ |
| Authorization server metadata at `/.well-known/oauth-authorization-server{path}` | RFC 8414 | ✅ |
| Encrypted self-contained access tokens: RFC 9068 JWS (`at+jwt`, RS256 / ES256) nested in a JWE (RSA-OAEP-256 or dir, A256GCM, `cty: JWT`); plain JWS / `alg: none` / other alg or enc / tampering rejected; JWKS with public signing keys only | RFC 9068, RFC 7516, RFC 7518 §4.3 / §4.5 / §5.3, RFC 7519 §5.2, RFC 7517 / 7638 | ✅ |
| CSPRNG for all secrets; hashed storage; constant-time comparison | 2.1 §7 | ✅ |
| Consent remembered per user + client | — | ✅ (pluggable UI) |
| DPoP / mTLS sender-constrained tokens | RFC 9449 / 8705 | ➖ |
| PAR, JAR, RAR, resource indicators, dynamic client registration, OpenID Connect | RFC 9126 / 9101 / 9396 / 8707 / 7591, OIDC | ➖ |
| Device authorization grant, token exchange | RFC 8628 / 8693 | ➖ |
| Revocation of a *foreign* client's token | RFC 7009 §2.1 | 200 without revoking (no token-existence oracle) |

Host responsibilities: TLS everywhere (issuer must be `https://` in production), CSRF protection and
clickjacking headers on the login / consent pages, user authentication, rate limiting of the token endpoint.

## Development

- Unit tests (no Swoole / DB): `php tests/extension_grant_test.php`.

- Packagist: `server/composer.json` requires `loongs/oauth: dev-main`. Local development: `server/composer.dev.json` path repo `../composer/oauth` (symlink).
- Smoke (local, gitignored): `php -d disable_functions= server/bin/smoke_oauth.php cli|co` — throwaway databases
  `loongs_oauth_t1/t2/t3` (dropped; t1 prefixed `app_` + unicode_ci, t3 created by `oauth:install` from a named connection), Redis under a random prefix (deleted), a 4-worker Swoole test server on `127.0.0.1:19501`
  (framework Router + OAuthRoutes + BearerMiddleware), full flows over real HTTP, concurrency via coroutines (co) or curl_multi (cli).
