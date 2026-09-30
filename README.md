# loongs/oauth

OAuth 2.1 authorization server and resource server for the loong-swoole stack (PHP 8.4, Swoole
coroutines), following **draft-ietf-oauth-v2-1** and the RFCs it builds on. The core is
framework-neutral and storage-agnostic (`OAuthRequest` in, `OAuthResponse` out, six repository
interfaces). Adapters: **loongs/orm** (MySQL, one set of tables per tenant), **loongs/cache** (Redis
codes / tokens), memory (tests), and **loongs/framework** (routes + bearer middleware).

```bash
composer require loongs/oauth      # once published; locally via a path repo (see "Development")
```

## Layout

```
src/
  AuthorizationServer.php     authorize (code + PKCE), token (authorization_code | refresh_token | client_credentials),
                              revoke (RFC 7009), introspect (RFC 7662), metadata (RFC 8414), jwks
  ResourceServer.php          bearer extraction (header / form body, never query), opaque + JWT validation, WWW-Authenticate
  ServerConfig.php            issuer, scopes, TTLs, token format, signing keys, policy switches (secure defaults)
  Pkce.php TokenInfo.php
  Authorization/              AuthorizationRequest, AuthorizationDecision, AuthorizationHandlerInterface (host login + consent),
                              CallableAuthorizationHandler
  Entity/                     Client, AuthorizationCode, AccessToken, RefreshToken, Consent (readonly)
  Storage/                    ClientRepositoryInterface AuthCodeRepositoryInterface AccessTokenRepositoryInterface
                              RefreshTokenRepositoryInterface TokenFamilyRepositoryInterface ConsentRepositoryInterface
                              PurgeableInterface StorageInterface Stores
                              MemoryStorage · OrmStorage (loongs/orm) · CacheTokenStorage (loongs/cache)
  Jwt/                        Jwt (compact JWS), SigningKey (RS256 / ES256, RFC 7638 kid), JwkSet (JWKS ⇄ PEM), Der, JwtException
  Http/                       OAuthRequest, OAuthResponse
  Framework/                  Bridge, OAuthRoutes, BearerMiddleware (loongs/framework)
  Exception/                  OAuthException (RFC 6749 §5.2 / RFC 6750 §3), RedirectableException
  Support/                    Crypto (CSPRNG, hashing, constant-time), Scope
database/mysql.sql            schema (6 tables, prefix oauth_)
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
$storage->install();                                 // database/mysql.sql, idempotent
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
- JWT access tokens (`accessTokenFormat: 'jwt'`, RFC 9068): header `typ: at+jwt`, claims `iss exp aud sub client_id iat jti scope`
  (+ `gty` for client_credentials); RS256 (≥2048-bit RSA) or ES256 (P-256) through openssl; the verifier takes the algorithm from
  the key registered under `kid` (no `alg: none`, no HS/RS confusion, `crit` rejected); `previousKeys` keeps rotated keys in the JWKS.
  JWTs are also stored by `jti`, so revocation and introspection work; a JWKS-only verifier cannot see revocation before `exp`.

## Multi-tenancy (loongs/orm)

`OrmStorage` resolves its connection on every statement, like every loongs/orm call:
`new OrmStorage($spec)` pins a tenant (name / array / DSN / ConnectionConfig), `new OrmStorage()` follows
the coroutine's `Orm::tenant()` scope, `->on($other)` rebinds. Give each tenant its own issuer
(`https://auth.example.com/{tenant}` → metadata at `/.well-known/oauth-authorization-server/{tenant}`).
A token, code or client secret of one tenant is unknown to the others (separate tables). Mixed storage:
`new Stores(clients: $orm, consents: $orm, codes: $cache, accessTokens: $cache, refreshTokens: $cache, families: $cache)`
with `CacheTokenStorage` on a per-tenant Redis prefix. `purgeExpired()` from a crontab process.

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
| JWT access tokens (`at+jwt`, required claims), JWKS, RS256 / ES256 | RFC 9068, RFC 7517/7518, RFC 7638 | ✅ |
| CSPRNG for all secrets; hashed storage; constant-time comparison | 2.1 §7 | ✅ |
| Consent remembered per user + client | — | ✅ (pluggable UI) |
| DPoP / mTLS sender-constrained tokens | RFC 9449 / 8705 | ➖ |
| PAR, JAR, RAR, resource indicators, dynamic client registration, OpenID Connect | RFC 9126 / 9101 / 9396 / 8707 / 7591, OIDC | ➖ |
| Device authorization grant, token exchange | RFC 8628 / 8693 | ➖ |
| Revocation of a *foreign* client's token | RFC 7009 §2.1 | 200 without revoking (no token-existence oracle) |

Host responsibilities: TLS everywhere (issuer must be `https://` in production), CSRF protection and
clickjacking headers on the login / consent pages, user authentication, rate limiting of the token endpoint.

## Development

- Local: `server/composer.dev.json` path repo `../composer/oauth` (symlink). Not in `server/composer.json` until published.
- Smoke (local, gitignored): `php -d disable_functions= server/bin/smoke_oauth.php cli|co` — throwaway databases
  `loongs_oauth_t1/t2` (dropped), Redis under a random prefix (deleted), a 4-worker Swoole test server on `127.0.0.1:19501`
  (framework Router + OAuthRoutes + BearerMiddleware), full flows over real HTTP, concurrency via coroutines (co) or curl_multi (cli).
