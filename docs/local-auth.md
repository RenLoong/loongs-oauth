# Local (no-DB) access-token authentication

## Goal

After the authorization server (e.g. Uuims) **issues** access tokens, **resource-server authentication** must rely only on `loongs/oauth` and **must not hit the database** on the hot path. Issue, refresh, and revoke may still use MySQL (`OrmStorage`).

Opaque tokens (`accessTokenFormat: opaque`) always need a store lookup. For no-DB auth, issue **JWE** access tokens (`ServerConfig::FORMAT_JWE`) and validate them with a **local** `ResourceServer`.

## First-class API

```php
use Loongs\OAuth\ResourceServer;

// From ServerConfig (preferred in resource apps that only hold keys):
$rs = ResourceServer::local($config);

// From an AuthorizationServer instance (uses its config; ignores stores):
$rs = ResourceServer::localFromServer($as);
// or
$rs = $as->localResourceServer();

$info = $rs->authenticate($request);   // or $rs->validate($bearerString)
```

`ResourceServer::fromServer($as)` remains the **store-backed** path (opaque + optional JWE with `checkRevocation`). Pass `fromServer($as, checkRevocation: false)` to keep the store for opaque tokens but skip JWE `jti` lookups.

`BearerMiddleware::for($as->localResourceServer(), 'profile')` works the same as with a store-backed RS.

## Error distinction

RFC 6750 still uses `error=invalid_token` for expired / revoked / invalid tokens. This package adds a structured **`reason`** so clients can choose refresh vs re-login:

| `reason`   | Meaning                                      | Client action                          |
|------------|----------------------------------------------|----------------------------------------|
| `expired`  | Access token past `exp` (+ leeway)           | Try `refresh_token`; else re-login     |
| `revoked`  | Explicitly revoked or token family revoked   | Re-login (refresh will fail)           |
| `invalid`  | Malformed, wrong iss/aud, unknown, etc.      | Re-login                               |

Surfaces:

- `OAuthException::$reason` / `->isExpired()` / `->isRevoked()`
- JSON body from `toResponse()` / `toArray()` includes `"reason"` when set
- `WWW-Authenticate` `error_description` is human-readable (`The access token expired.` / `…revoked.` / `…invalid.`)

Constants: `OAuthException::REASON_EXPIRED`, `REASON_REVOKED`, `REASON_INVALID`.

## Security model when skipping per-request revocation lookup

Local mode **cannot** see a mid-TTL revoke of an access token. Mitigations:

1. **Short access TTL** — keep `accessTokenTtl` short (minutes, not hours). Stolen or revoked access tokens die quickly.
2. **Refresh rotation** — rotate refresh tokens; reuse of a rotated refresh revokes the family (`invalid_grant` on refresh). Forced logout should revoke the **refresh** / family at the AS.
3. **Forced logout / revoke** — call the revocation endpoint (or revoke the family). Effects:
   - Next **refresh** fails immediately (DB).
   - Existing **access** JWEs remain acceptable to local RS until `exp`.
   - There is **no denylist** in local mode; if you need instant cut-off, use store-backed `fromServer()` / share the token store, or wait for expiry.
4. **Key rotation** — rotate signing / encryption keys; old tokens fail decrypt/verify after previous keys are dropped from `previousKeys` / `previousEncryptionKeys`.
5. **Do not weaken JWE** — still nested RFC 9068 JWS inside JWE (RSA-OAEP-256 or dir + A256GCM). Plain JWS access tokens remain rejected.

## Uuims wiring (sketch)

```php
// Issue with JWE:
new ServerConfig(issuer: $iss, accessTokenFormat: ServerConfig::FORMAT_JWE, signingKey: $sig, encryptionKey: $enc, accessTokenTtl: 900, /* ... */);

// Auth.check / middleware — local only:
$rs = ResourceServer::local($config); // or $oauth->localResourceServer()
try {
    $info = $rs->authenticate($request);
} catch (OAuthException $e) {
    if ($e->error === 'invalid_token' && $e->isExpired()) {
        // tell client: refresh or re-login
    } elseif ($e->error === 'invalid_token') {
        // re-login
    }
    throw $e;
}
```

Issuance / refresh / revoke keep using `AuthorizationServer` + `OrmStorage` unchanged.
