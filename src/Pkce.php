<?php

declare(strict_types=1);

namespace Loongs\OAuth;

use Loongs\OAuth\Support\Crypto;

/** Proof Key for Code Exchange (RFC 7636, required by OAuth 2.1). */
final class Pkce
{
    public const string S256 = 'S256';
    public const string PLAIN = 'plain';

    private const string SYNTAX = '/^[A-Za-z0-9\-._~]{43,128}$/D';

    public static function isValidVerifier(string $v): bool
    {
        return preg_match(self::SYNTAX, $v) === 1;
    }

    public static function isValidChallenge(string $c, string $method): bool
    {
        return $method === self::S256 ? preg_match('/^[A-Za-z0-9_-]{43}$/D', $c) === 1 : preg_match(self::SYNTAX, $c) === 1;
    }

    /** Client side: a new code_verifier (43 chars) … */
    public static function verifier(): string
    {
        return Crypto::token(32);
    }

    /** … and its S256 code_challenge. */
    public static function challenge(string $verifier): string
    {
        return Crypto::base64UrlEncode(hash('sha256', $verifier, true));
    }

    /** Constant-time verification of a code_verifier against the stored challenge. */
    public static function verify(string $verifier, string $challenge, string $method): bool
    {
        if (!self::isValidVerifier($verifier)) {
            return false;
        }
        $computed = match ($method) {
            self::S256 => self::challenge($verifier),
            self::PLAIN => $verifier,
            default => null,
        };

        return $computed !== null && Crypto::equals($challenge, $computed);
    }
}
