<?php

declare(strict_types=1);

namespace Loongs\OAuth\Jwt;

use Loongs\OAuth\Support\Crypto;

/**
 * Compact JWS for access tokens (RFC 7515 / 7519 / 9068). Only RS256 and ES256 are accepted — the
 * algorithm comes from the key registered under the token's kid, never from the header alone
 * ("alg": "none" and HS* confusion are impossible).
 */
final class Jwt
{
    /** @param array<string, mixed> $claims @param array<string, mixed> $header */
    public static function encode(array $claims, SigningKey $key, array $header = []): string
    {
        $h = ['alg' => $key->alg, 'typ' => $header['typ'] ?? 'JWT', 'kid' => $key->kid] + $header;
        $input = Crypto::base64UrlEncode((string) json_encode($h, JSON_UNESCAPED_SLASHES))
            . '.' . Crypto::base64UrlEncode((string) json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

        return $input . '.' . Crypto::base64UrlEncode($key->sign($input));
    }

    public static function looksLikeJwt(string $token): bool
    {
        return substr_count($token, '.') === 2 && str_starts_with($token, 'eyJ');
    }

    /**
     * Verify the signature and return [header, claims]; claim checks (iss, aud, exp, typ) are the caller's.
     *
     * @return array{0: array<string, mixed>, 1: array<string, mixed>}
     * @throws JwtException
     */
    public static function decode(string $jwt, JwkSet $keys): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new JwtException('malformed');
        }
        [$h64, $c64, $s64] = $parts;
        $hj = Crypto::base64UrlDecode($h64);
        $cj = Crypto::base64UrlDecode($c64);
        $sig = Crypto::base64UrlDecode($s64);
        $header = $hj !== null ? json_decode($hj, true) : null;
        $claims = $cj !== null ? json_decode($cj, true) : null;
        if (!is_array($header) || !is_array($claims) || $sig === null || $sig === '') {
            throw new JwtException('malformed');
        }
        if (isset($header['crit'])) {
            throw new JwtException('unsupported crit header');
        }
        $key = $keys->get((string) ($header['kid'] ?? ''));
        if ($key === null) {
            throw new JwtException('unknown kid');
        }
        if (($header['alg'] ?? null) !== $key['alg']) {
            throw new JwtException('alg mismatch');
        }
        if ($key['alg'] === 'ES256') {
            $sig = Der::ecdsaRawToDer($sig);
            if ($sig === null) {
                throw new JwtException('bad signature');
            }
        }
        if (openssl_verify($h64 . '.' . $c64, $sig, $key['pem'], OPENSSL_ALGO_SHA256) !== 1) {
            throw new JwtException('bad signature');
        }

        return [$header, $claims];
    }
}
