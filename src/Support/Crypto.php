<?php

declare(strict_types=1);

namespace Loongs\OAuth\Support;

/**
 * CSPRNG tokens, token hashing, client-secret hashing, constant-time comparison, base64url.
 *
 * Every secret comes from random_bytes() (the OS CSPRNG). Tokens and codes carry >= 256 bits of
 * entropy, so a keyed SHA-256 (HMAC with an optional server pepper) is enough to store them: the
 * database only ever sees the hash. Client secrets are hashed with password_hash() (Argon2id when
 * available, else bcrypt) because they may be chosen by humans.
 */
final class Crypto
{
    /** A dummy hash verified when a client does not exist, so unknown and known client ids take the same time. */
    private static ?string $dummyHash = null;

    /** URL-safe random token: $bytes of CSPRNG output, base64url without padding (32 bytes → 43 chars). */
    public static function token(int $bytes = 32): string
    {
        if ($bytes < 16) {
            throw new \InvalidArgumentException('Tokens need at least 128 bits of entropy.');
        }

        return self::base64UrlEncode(random_bytes($bytes));
    }

    /** Random hex identifier (family ids, jti). */
    public static function id(int $bytes = 16): string
    {
        return bin2hex(random_bytes($bytes));
    }

    /** Storage hash of a token / code (64 hex chars). */
    public static function hashToken(string $token, string $pepper = ''): string
    {
        return hash_hmac('sha256', $token, $pepper);
    }

    public static function hashSecret(string $secret): string
    {
        return password_hash($secret, defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT);
    }

    /** Constant-time secret check. With $hash = null (unknown client) a dummy hash is still verified. */
    public static function verifySecret(string $secret, ?string $hash): bool
    {
        if ($hash === null || $hash === '') {
            password_verify($secret, self::$dummyHash ??= self::hashSecret(self::token()));

            return false;
        }

        return password_verify($secret, $hash);
    }

    /** Constant-time string comparison. */
    public static function equals(string $known, string $user): bool
    {
        return hash_equals($known, $user);
    }

    public static function base64UrlEncode(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    /** Strict base64url decode (no padding, alphabet A-Z a-z 0-9 - _). Null when malformed. */
    public static function base64UrlDecode(string $b64): ?string
    {
        if ($b64 === '' ) {
            return '';
        }
        if (!preg_match('/^[A-Za-z0-9_-]+$/D', $b64) || strlen($b64) % 4 === 1) {
            return null;
        }
        $raw = base64_decode(strtr($b64, '-_', '+/'), true);

        return $raw === false ? null : $raw;
    }
}
