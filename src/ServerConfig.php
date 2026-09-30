<?php

declare(strict_types=1);

namespace Loongs\OAuth;

use Loongs\OAuth\Jwt\SigningKey;

/**
 * Authorization-server settings. Secure defaults: PKCE required for every client, S256 only, 60 s
 * single-use codes, refresh-token rotation for every client, opaque hashed access tokens.
 */
final readonly class ServerConfig
{
    public const string FORMAT_OPAQUE = 'opaque';
    public const string FORMAT_JWT = 'jwt';

    /** @var list<SigningKey> */
    public array $verificationKeys;

    /**
     * @param string                $issuer          https://… (no query / fragment); also the RFC 9207 iss value
     * @param list<string>          $scopes          scopes_supported
     * @param list<string>          $defaultScopes   used when a request has no scope
     * @param string                $accessTokenFormat 'opaque' | 'jwt' (RFC 9068)
     * @param SigningKey|null       $signingKey      required for 'jwt'
     * @param list<SigningKey>      $previousKeys    still published in the JWKS during key rotation
     * @param string|null           $audience        JWT aud (default: the issuer)
     * @param array<string, string> $endpoints       paths or URLs: authorization, token, revocation, introspection, jwks
     * @param string                $tokenPepper     HMAC key for stored token hashes ('' = plain SHA-256); keep constant
     */
    public function __construct(
        public string $issuer,
        public array $scopes = [],
        public array $defaultScopes = [],
        public int $authCodeTtl = 60,
        public int $accessTokenTtl = 3600,
        public int $refreshTokenTtl = 2_592_000,
        public string $accessTokenFormat = self::FORMAT_OPAQUE,
        public ?SigningKey $signingKey = null,
        array $previousKeys = [],
        public ?string $audience = null,
        public bool $requirePkce = true,
        public bool $allowPlainPkce = false,
        public bool $rotateConfidentialRefreshTokens = true,
        public bool $strictClientAuthMethod = true,
        public int $jwtLeeway = 30,
        public array $endpoints = [],
        public string $tokenPepper = '',
        public string $realm = 'oauth',
    ) {
        $p = parse_url($issuer);
        if ($p === false || !isset($p['scheme'], $p['host']) || isset($p['query']) || isset($p['fragment'])) {
            throw new \InvalidArgumentException('issuer must be an absolute URL without query or fragment (RFC 8414 §2).');
        }
        if ($accessTokenFormat === self::FORMAT_JWT && $signingKey === null) {
            throw new \InvalidArgumentException('JWT access tokens need a signingKey.');
        }
        if (!in_array($accessTokenFormat, [self::FORMAT_OPAQUE, self::FORMAT_JWT], true)) {
            throw new \InvalidArgumentException("Unknown access token format [{$accessTokenFormat}].");
        }
        if ($authCodeTtl < 1 || $authCodeTtl > 600) {
            throw new \InvalidArgumentException('authCodeTtl must be 1..600 seconds (codes are short-lived).');
        }
        $this->verificationKeys = $signingKey !== null ? [$signingKey, ...$previousKeys] : $previousKeys;
    }

    public function endpoint(string $name): string
    {
        $default = ['authorization' => '/oauth/authorize', 'token' => '/oauth/token', 'revocation' => '/oauth/revoke',
            'introspection' => '/oauth/introspect', 'jwks' => '/oauth/jwks'][$name] ?? throw new \InvalidArgumentException("Unknown endpoint [{$name}].");
        $v = $this->endpoints[$name] ?? $default;

        return preg_match('#^https?://#i', $v) ? $v : rtrim($this->issuer, '/') . '/' . ltrim($v, '/');
    }

    public function audience(): string
    {
        return $this->audience ?? $this->issuer;
    }
}
