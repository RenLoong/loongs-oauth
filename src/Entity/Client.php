<?php

declare(strict_types=1);

namespace Loongs\OAuth\Entity;

use Loongs\OAuth\Support\Crypto;

/**
 * A registered client. Confidential clients have a hashed secret and authenticate at the token
 * endpoint with client_secret_basic or client_secret_post; public clients use "none" (+ PKCE).
 */
final readonly class Client
{
    public const string AUTH_BASIC = 'client_secret_basic';
    public const string AUTH_POST = 'client_secret_post';
    public const string AUTH_NONE = 'none';

    /**
     * @param list<string> $redirectUris exact-match redirect URIs (no fragment)
     * @param list<string> $grantTypes   authorization_code | refresh_token | client_credentials
     * @param list<string> $scopes       scopes this client may request
     */
    public function __construct(
        public string $id,
        public string $name,
        public ?string $secretHash,
        public array $redirectUris,
        public array $grantTypes,
        public array $scopes,
        public string $tokenEndpointAuthMethod,
        public bool $canIntrospect = false,
        public int $createdAt = 0,
    ) {
        if (!in_array($tokenEndpointAuthMethod, [self::AUTH_BASIC, self::AUTH_POST, self::AUTH_NONE], true)) {
            throw new \InvalidArgumentException("Unsupported token_endpoint_auth_method [{$tokenEndpointAuthMethod}].");
        }
        if (($tokenEndpointAuthMethod === self::AUTH_NONE) !== ($secretHash === null)) {
            throw new \InvalidArgumentException('Public clients (auth method "none") have no secret; confidential clients need one.');
        }
        foreach ($redirectUris as $uri) {
            self::assertRedirectUri($uri);
        }
        foreach ($grantTypes as $g) {
            if (!in_array($g, ['authorization_code', 'refresh_token', 'client_credentials'], true)) {
                throw new \InvalidArgumentException("Grant type [{$g}] is not supported by OAuth 2.1 / this server.");
            }
        }
        if ($secretHash === null && in_array('client_credentials', $grantTypes, true)) {
            throw new \InvalidArgumentException('client_credentials requires a confidential client.');
        }
    }

    /**
     * New confidential client + its plaintext secret (show it once; only the hash is stored).
     *
     * @param list<string> $redirectUris
     * @param list<string> $grantTypes
     * @param list<string> $scopes
     * @return array{0: self, 1: string}
     */
    public static function confidential(string $id, string $name, array $redirectUris, array $grantTypes, array $scopes,
        string $authMethod = self::AUTH_BASIC, bool $canIntrospect = false, ?string $secret = null): array
    {
        $secret ??= Crypto::token(32);

        return [new self($id, $name, Crypto::hashSecret($secret), $redirectUris, $grantTypes, $scopes, $authMethod, $canIntrospect, time()), $secret];
    }

    /**
     * @param list<string> $redirectUris
     * @param list<string> $scopes
     */
    public static function public(string $id, string $name, array $redirectUris, array $scopes, bool $refreshTokens = true): self
    {
        return new self($id, $name, null, $redirectUris, $refreshTokens ? ['authorization_code', 'refresh_token'] : ['authorization_code'], $scopes, self::AUTH_NONE, false, time());
    }

    public function isConfidential(): bool
    {
        return $this->secretHash !== null;
    }

    public function allowsGrant(string $grant): bool
    {
        return in_array($grant, $this->grantTypes, true);
    }

    /** Absolute URI without fragment (RFC 6749 §3.1.2). */
    public static function assertRedirectUri(string $uri): void
    {
        $p = parse_url($uri);
        if ($p === false || !isset($p['scheme']) || isset($p['fragment']) || str_contains($uri, '#')) {
            throw new \InvalidArgumentException("Invalid redirect URI [{$uri}]: absolute URI without fragment required.");
        }
    }
}
