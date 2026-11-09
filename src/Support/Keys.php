<?php

declare(strict_types=1);

namespace Loongs\OAuth\Support;

use Loongs\OAuth\Jwt\SigningKey;

/**
 * Typed CSPRNG material for loongs/oauth.
 *
 * Types:
 *   jwt            — asymmetric signing key for nested JWE access tokens (SigningKey, RS256 / ES256)
 *   sk             — opaque secret key with "sk_" prefix (client secrets / API secrets); store via Crypto::hashSecret
 *   token          — short-lived access-token material (256-bit, base64url)
 *   refresh_token  — long-lived refresh-token material (384-bit, base64url)
 *
 * Authorization codes and PKCE verifiers stay on Crypto::token(); they are not key types.
 */
final class Keys
{
    public const string JWT = 'jwt';
    public const string SK = 'sk';
    public const string TOKEN = 'token';
    public const string REFRESH_TOKEN = 'refresh_token';

    /** @var list<string> */
    public const array TYPES = [self::JWT, self::SK, self::TOKEN, self::REFRESH_TOKEN];

    public const string SK_PREFIX = 'sk_';
    public const int TOKEN_BYTES = 32;
    public const int REFRESH_TOKEN_BYTES = 48;
    public const int SK_BYTES = 32;

    /**
     * Generate material by type.
     *
     * @return SigningKey|string SigningKey for jwt; string for sk / token / refresh_token
     */
    public static function generate(string $type, string $alg = 'ES256', ?string $kid = null): SigningKey|string
    {
        return match ($type) {
            self::JWT => self::jwt($alg, $kid),
            self::SK => self::sk(),
            self::TOKEN => self::token(),
            self::REFRESH_TOKEN => self::refreshToken(),
            default => throw new \InvalidArgumentException(
                "Unknown key type [{$type}] (jwt | sk | token | refresh_token).",
            ),
        };
    }

    /** JWT signing key (RS256 / ES256). Same as SigningKey::generate(). */
    public static function jwt(string $alg = 'ES256', ?string $kid = null): SigningKey
    {
        return SigningKey::generate($alg, $kid);
    }

    /**
     * Opaque secret key: "sk_" + base64url(32 bytes). Show once; persist only Crypto::hashSecret(...).
     */
    public static function sk(int $bytes = self::SK_BYTES): string
    {
        if ($bytes < 16) {
            throw new \InvalidArgumentException('sk secrets need at least 128 bits of entropy.');
        }

        return self::SK_PREFIX . Crypto::token($bytes);
    }

    /** Short access-token material (256-bit). Hashed at rest with Crypto::hashToken. */
    public static function token(): string
    {
        return Crypto::token(self::TOKEN_BYTES);
    }

    /** Long refresh-token material (384-bit). Hashed at rest with Crypto::hashToken. */
    public static function refreshToken(): string
    {
        return Crypto::token(self::REFRESH_TOKEN_BYTES);
    }

    public static function isSk(string $value): bool
    {
        return str_starts_with($value, self::SK_PREFIX);
    }
}