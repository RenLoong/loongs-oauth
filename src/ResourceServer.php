<?php

declare(strict_types=1);

namespace Loongs\OAuth;

use Loongs\OAuth\Exception\OAuthException;
use Loongs\OAuth\Http\OAuthRequest;
use Loongs\OAuth\Jwt\EncryptionKey;
use Loongs\OAuth\Jwt\Jwe;
use Loongs\OAuth\Jwt\JwkSet;
use Loongs\OAuth\Jwt\Jwt;
use Loongs\OAuth\Jwt\JwtException;
use Loongs\OAuth\Storage\AccessTokenRepositoryInterface;
use Loongs\OAuth\Storage\TokenFamilyRepositoryInterface;
use Loongs\OAuth\Support\Crypto;
use Loongs\OAuth\Support\Scope;

/**
 * Validates bearer access tokens (RFC 6750 as profiled by OAuth 2.1): Authorization header or form
 * body only — a token in the query string is rejected. Opaque tokens are looked up by hash.
 * Self-contained tokens must be encrypted: a JWE (RSA-OAEP-256 or dir, A256GCM) whose plaintext is a
 * signed RFC 9068 JWT (RS256 / ES256) — decrypted with $decryptionKeys, signature checked with $jwks,
 * claims validated and, when a token store is configured with checkRevocation, checked for revocation
 * by jti. A plain (unencrypted) JWS / JWT is always rejected.
 *
 * Local (no-DB) mode: ResourceServer::local() / localFromServer() / AuthorizationServer::localResourceServer()
 * — JWE decrypt + verify only; never hits the token store. Errors distinguish expired vs revoked vs
 * invalid (OAuthException::$reason + WWW-Authenticate error_description).
 */
final readonly class ResourceServer
{
    public function __construct(
        public string $issuer,
        private ?AccessTokenRepositoryInterface $tokens = null,
        private ?TokenFamilyRepositoryInterface $families = null,
        private ?JwkSet $jwks = null,
        private array $decryptionKeys = [],
        private ?string $audience = null,
        private string $tokenPepper = '',
        public string $realm = 'oauth',
        private int $leeway = 30,
        private bool $checkRevocation = true,
    ) {
        if ($tokens === null && ($jwks === null || $decryptionKeys === [])) {
            throw new \InvalidArgumentException('A resource server needs a token store (opaque tokens) and/or a JWKS + decryption keys (JWE access tokens).');
        }
        foreach ($decryptionKeys as $k) {
            if (!$k instanceof EncryptionKey || !$k->canDecrypt()) {
                throw new \InvalidArgumentException('decryptionKeys must be EncryptionKeys that can decrypt.');
            }
        }
    }

    /**
     * Store-backed resource server (opaque + optional JWE with per-request revocation lookup).
     * Pass $checkRevocation=false to keep the store for opaque tokens but skip JWE jti lookups.
     */
    public static function fromServer(AuthorizationServer $as, bool $checkRevocation = true): self
    {
        $c = $as->config;

        return new self(
            $c->issuer,
            $as->stores->accessTokens,
            $as->stores->families,
            $c->verificationKeys !== [] ? JwkSet::fromSigningKeys(...$c->verificationKeys) : null,
            $c->decryptionKeys,
            $c->audience(),
            $c->tokenPepper,
            $c->realm,
            $c->jwtLeeway,
            $checkRevocation,
        );
    }

    /**
     * First-class local (no-DB) resource server for self-contained JWE access tokens.
     * Decrypt + verify + claim check only; never attaches a token store. Issue / refresh / revoke
     * still use AuthorizationServer + DB. Requires JWE signing + decryption keys on $config.
     *
     * @see docs/local-auth.md
     */
    public static function local(ServerConfig $config): self
    {
        if ($config->verificationKeys === [] || $config->decryptionKeys === []) {
            throw new \InvalidArgumentException('Local resource server needs verificationKeys (signing JWKS) and decryptionKeys (JWE).');
        }

        return new self(
            $config->issuer,
            tokens: null,
            families: null,
            jwks: JwkSet::fromSigningKeys(...$config->verificationKeys),
            decryptionKeys: $config->decryptionKeys,
            audience: $config->audience(),
            tokenPepper: $config->tokenPepper,
            realm: $config->realm,
            leeway: $config->jwtLeeway,
            checkRevocation: false,
        );
    }

    /** Convenience: local(no-DB) RS from an AuthorizationServer's config (ignores its stores). */
    public static function localFromServer(AuthorizationServer $as): self
    {
        return self::local($as->config);
    }

    /** True when this instance never looks up the access-token store on authenticate/validate. */
    public function isLocal(): bool
    {
        return $this->tokens === null;
    }

    /**
     * Extract + validate the request's bearer token and require $scopes.
     *
     * @param list<string> $scopes
     * @throws OAuthException 400 invalid_request / 401 invalid_token / 403 insufficient_scope, with WWW-Authenticate
     */
    public function authenticate(OAuthRequest $request, array $scopes = []): TokenInfo
    {
        if (array_key_exists('access_token', $request->query)) {
            throw $this->error('invalid_request', 'Access tokens in the URI query are not allowed (OAuth 2.1); use the Authorization header.', 400);
        }
        $fromHeader = null;
        $auth = $request->header('authorization');
        if ($auth !== null && preg_match('/^Bearer[ ]+(.*)$/i', trim($auth), $m)) {
            $fromHeader = trim($m[1]);
            if ($fromHeader === '' || !preg_match('#^[A-Za-z0-9\-._~+/]+=*$#D', $fromHeader)) {
                throw $this->error('invalid_request', 'Malformed bearer token.', 400);
            }
        }
        $fromBody = null;
        if ($request->method !== 'GET' && $request->isForm() && array_key_exists('access_token', $request->post)) {
            $fromBody = $request->param('access_token', 'post') ?? '';
        }
        if ($fromHeader !== null && $fromBody !== null) {
            throw $this->error('invalid_request', 'More than one method used to send the access token.', 400);
        }
        $token = $fromHeader ?? $fromBody;
        if ($token === null || $token === '') {
            throw new OAuthException('invalid_token', 'Missing access token.', 401, ['WWW-Authenticate' => $this->challenge()]);
        }
        $info = $this->validate($token);
        if ($scopes !== [] && !$info->hasScope(...$scopes)) {
            throw $this->error('insufficient_scope', 'The access token lacks the required scope.', 403, $scopes);
        }

        return $info;
    }

    /**
     * @throws OAuthException invalid_token (401) with reason expired|revoked|invalid
     */
    public function validate(string $token, ?int $now = null): TokenInfo
    {
        $now ??= time();
        // opaque tokens never contain '.'; a plain JWS is rejected inside validateJwe
        return str_contains($token, '.')
            ? $this->validateJwe($token, $now)
            : $this->validateOpaque($token, $now);
    }

    private function validateOpaque(string $token, int $now): TokenInfo
    {
        if ($this->tokens === null) {
            throw $this->tokenError(OAuthException::REASON_INVALID, 'The access token is invalid.');
        }
        $t = $this->tokens->findAccessToken(Crypto::hashToken($token, $this->tokenPepper));
        if ($t === null || $t->format !== ServerConfig::FORMAT_OPAQUE) {
            throw $this->tokenError(OAuthException::REASON_INVALID, 'The access token is invalid.');
        }
        if ($t->revokedAt !== null || ($this->families?->isFamilyRevoked($t->familyId) ?? false)) {
            throw $this->tokenError(OAuthException::REASON_REVOKED, 'The access token has been revoked.');
        }
        if ($now >= $t->expiresAt) {
            throw $this->tokenError(OAuthException::REASON_EXPIRED, 'The access token expired.');
        }

        return new TokenInfo($t->clientId, $t->userId, $t->scopes, $t->expiresAt, $t->issuedAt, $t->jti, $t->format);
    }

    /**
     * Decrypt + verify an encrypted access token and return its claims, or null. Rejects plain JWS,
     * alg none / unsupported alg or enc, tampered header / key / IV / ciphertext / tag, wrong keys,
     * a missing or wrong cty, an inner token that is not a signed at+jwt.
     *
     * @return array<string, mixed>|null
     */
    public function decodeJwe(string $token): ?array
    {
        if ($this->jwks === null || $this->decryptionKeys === [] || !Jwe::looksLikeJwe($token)) {
            return null;
        }
        try {
            [$outer, $inner] = Jwe::decrypt($token, $this->decryptionKeys);
            if (strtoupper((string) ($outer['cty'] ?? '')) !== 'JWT' || !Jwt::looksLikeJwt($inner)) {
                return null;
            }
            [$h, $c] = Jwt::decode($inner, $this->jwks);
        } catch (JwtException) {
            return null;
        }
        $typ = strtolower((string) ($h['typ'] ?? ''));

        return in_array($typ, ['at+jwt', 'application/at+jwt'], true) ? $c : null;
    }

    private function validateJwe(string $token, int $now): TokenInfo
    {
        $c = $this->decodeJwe($token);
        if ($c === null) {
            throw $this->tokenError(OAuthException::REASON_INVALID, 'The access token is invalid.');
        }
        $aud = $c['aud'] ?? null;
        $auds = is_array($aud) ? $aud : [$aud];
        if (($c['iss'] ?? null) !== $this->issuer
            || !in_array($this->audience ?? $this->issuer, $auds, true)
            || !is_string($c['client_id'] ?? null) || !is_string($c['jti'] ?? null) || !is_string($c['sub'] ?? null)) {
            throw $this->tokenError(OAuthException::REASON_INVALID, 'The access token is invalid.');
        }
        if (!is_int($c['exp'] ?? null) || $now >= $c['exp'] + $this->leeway) {
            throw $this->tokenError(OAuthException::REASON_EXPIRED, 'The access token expired.');
        }
        if (isset($c['nbf']) && (!is_int($c['nbf']) || $now + $this->leeway < $c['nbf'])) {
            throw $this->tokenError(OAuthException::REASON_INVALID, 'The access token is not yet valid.');
        }
        $userId = $c['sub'] === $c['client_id'] && ($c['gty'] ?? null) === 'client_credentials' ? null : $c['sub'];
        if ($this->tokens !== null && $this->checkRevocation) {
            $t = $this->tokens->findAccessToken(self::jtiHash($c['jti'], $this->tokenPepper));
            if ($t === null || $t->format !== ServerConfig::FORMAT_JWE || $t->clientId !== $c['client_id']) {
                throw $this->tokenError(OAuthException::REASON_INVALID, 'The access token is invalid.');
            }
            if ($t->revokedAt !== null || ($this->families?->isFamilyRevoked($t->familyId) ?? false)) {
                throw $this->tokenError(OAuthException::REASON_REVOKED, 'The access token has been revoked.');
            }
            $userId = $t->userId;
        }

        try {
            $scopes = Scope::parse(is_string($c['scope'] ?? null) ? $c['scope'] : '');
        } catch (OAuthException) {
            throw $this->tokenError(OAuthException::REASON_INVALID, 'The access token is invalid.');
        }

        return new TokenInfo($c['client_id'], $userId, $scopes, $c['exp'], (int) ($c['iat'] ?? 0), $c['jti'], ServerConfig::FORMAT_JWE, $c);
    }

    /** Storage key of a JWE access token (hash of its jti, domain-separated from opaque tokens). */
    public static function jtiHash(string $jti, string $pepper = ''): string
    {
        return Crypto::hashToken('jti:' . $jti, $pepper);
    }

    /** @param list<string> $scopes */
    public function error(string $error, string $description, int $status, array $scopes = [], ?string $reason = null): OAuthException
    {
        return new OAuthException($error, $description, $status, ['WWW-Authenticate' => $this->challenge($error, $description, $scopes)], reason: $reason);
    }

    private function tokenError(string $reason, string $description): OAuthException
    {
        return $this->error('invalid_token', $description, 401, reason: $reason);
    }

    /** RFC 6750 §3 challenge. No error attributes when the request had no token at all. @param list<string> $scopes */
    public function challenge(?string $error = null, ?string $description = null, array $scopes = []): string
    {
        $q = static fn (string $v): string => '"' . addcslashes($v, '"\\') . '"';
        $parts = ['realm=' . $q($this->realm)];
        if ($error !== null) {
            $parts[] = 'error=' . $q($error);
            if ($description !== null && $description !== '') {
                $parts[] = 'error_description=' . $q($description);
            }
        }
        if ($scopes !== []) {
            $parts[] = 'scope=' . $q(implode(' ', $scopes));
        }

        return 'Bearer ' . implode(', ', $parts);
    }
}
