<?php

declare(strict_types=1);

namespace Loongs\OAuth;

use Loongs\OAuth\Exception\OAuthException;
use Loongs\OAuth\Http\OAuthRequest;
use Loongs\OAuth\Jwt\JwkSet;
use Loongs\OAuth\Jwt\Jwt;
use Loongs\OAuth\Jwt\JwtException;
use Loongs\OAuth\Storage\AccessTokenRepositoryInterface;
use Loongs\OAuth\Storage\TokenFamilyRepositoryInterface;
use Loongs\OAuth\Support\Crypto;
use Loongs\OAuth\Support\Scope;

/**
 * Validates bearer access tokens (RFC 6750 as profiled by OAuth 2.1): Authorization header or form
 * body only — a token in the query string is rejected. Opaque tokens are looked up by hash; JWT
 * access tokens (RFC 9068) are verified against a JWKS and, when a token store is configured, also
 * checked for revocation by jti. Errors carry the WWW-Authenticate challenge.
 */
final readonly class ResourceServer
{
    public function __construct(
        public string $issuer,
        private ?AccessTokenRepositoryInterface $tokens = null,
        private ?TokenFamilyRepositoryInterface $families = null,
        private ?JwkSet $jwks = null,
        private ?string $audience = null,
        private string $tokenPepper = '',
        public string $realm = 'oauth',
        private int $leeway = 30,
        private bool $checkRevocation = true,
    ) {
        if ($tokens === null && $jwks === null) {
            throw new \InvalidArgumentException('A resource server needs a token store (opaque tokens) and/or a JWKS (JWT access tokens).');
        }
    }

    public static function fromServer(AuthorizationServer $as): self
    {
        $c = $as->config;

        return new self($c->issuer, $as->stores->accessTokens, $as->stores->families,
            $c->verificationKeys !== [] ? JwkSet::fromSigningKeys(...$c->verificationKeys) : null,
            $c->audience(), $c->tokenPepper, $c->realm, $c->jwtLeeway);
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

    /** @throws OAuthException invalid_token (401) */
    public function validate(string $token, ?int $now = null): TokenInfo
    {
        $now ??= time();
        $info = $this->jwks !== null && Jwt::looksLikeJwt($token) ? $this->validateJwt($token, $now) : $this->validateOpaque($token, $now);

        return $info ?? throw $this->error('invalid_token', 'The access token is invalid, expired or revoked.', 401);
    }

    private function validateOpaque(string $token, int $now): ?TokenInfo
    {
        if ($this->tokens === null) {
            return null;
        }
        $t = $this->tokens->findAccessToken(Crypto::hashToken($token, $this->tokenPepper));
        if ($t === null || $t->format !== ServerConfig::FORMAT_OPAQUE || $t->revokedAt !== null || $now >= $t->expiresAt
            || ($this->families?->isFamilyRevoked($t->familyId) ?? false)) {
            return null;
        }

        return new TokenInfo($t->clientId, $t->userId, $t->scopes, $t->expiresAt, $t->issuedAt, $t->jti, $t->format);
    }

    private function validateJwt(string $token, int $now): ?TokenInfo
    {
        try {
            [$h, $c] = Jwt::decode($token, $this->jwks);
        } catch (JwtException) {
            return null;
        }
        $typ = strtolower((string) ($h['typ'] ?? ''));
        $aud = $c['aud'] ?? null;
        $auds = is_array($aud) ? $aud : [$aud];
        if (!in_array($typ, ['at+jwt', 'application/at+jwt'], true)
            || ($c['iss'] ?? null) !== $this->issuer
            || !in_array($this->audience ?? $this->issuer, $auds, true)
            || !is_int($c['exp'] ?? null) || $now >= $c['exp'] + $this->leeway
            || (isset($c['nbf']) && (!is_int($c['nbf']) || $now + $this->leeway < $c['nbf']))
            || !is_string($c['client_id'] ?? null) || !is_string($c['jti'] ?? null) || !is_string($c['sub'] ?? null)) {
            return null;
        }
        $userId = $c['sub'] === $c['client_id'] && ($c['gty'] ?? null) === 'client_credentials' ? null : $c['sub'];
        if ($this->tokens !== null && $this->checkRevocation) {
            $t = $this->tokens->findAccessToken(self::jtiHash($c['jti'], $this->tokenPepper));
            if ($t === null || $t->format !== ServerConfig::FORMAT_JWT || $t->revokedAt !== null || $t->clientId !== $c['client_id']
                || ($this->families?->isFamilyRevoked($t->familyId) ?? false)) {
                return null;
            }
            $userId = $t->userId;
        }

        try {
            $scopes = Scope::parse(is_string($c['scope'] ?? null) ? $c['scope'] : '');
        } catch (OAuthException) {
            return null;
        }

        return new TokenInfo($c['client_id'], $userId, $scopes, $c['exp'], (int) ($c['iat'] ?? 0), $c['jti'], ServerConfig::FORMAT_JWT, $c);
    }

    /** Storage key of a JWT access token (hash of its jti, domain-separated from opaque tokens). */
    public static function jtiHash(string $jti, string $pepper = ''): string
    {
        return Crypto::hashToken('jti:' . $jti, $pepper);
    }

    /** @param list<string> $scopes */
    public function error(string $error, string $description, int $status, array $scopes = []): OAuthException
    {
        return new OAuthException($error, $description, $status, ['WWW-Authenticate' => $this->challenge($error, $description, $scopes)]);
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
