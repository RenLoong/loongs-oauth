<?php

declare(strict_types=1);

namespace Loongs\OAuth\Jwt;

use Loongs\OAuth\Support\Crypto;

/**
 * JWE compact serialization (RFC 7516) with key management RSA-OAEP-256 or dir, content encryption
 * A256GCM only (RFC 7518 §4.3, §4.5, §5.3). No zip, no crit. Used for nested JWTs: a signed JWS
 * (RS256 / ES256) is the plaintext, cty = "JWT".
 */
final class Jwe
{
    public const string ENC = 'A256GCM';

    /** @param array<string, mixed> $header extra protected header members (typ, cty …) */
    public static function encrypt(string $plaintext, EncryptionKey $key, array $header = []): string
    {
        if (!$key->canEncrypt()) {
            throw new JwtException('key cannot encrypt');
        }
        $h = ['alg' => $key->alg, 'enc' => self::ENC, 'kid' => $key->kid] + $header;
        $h['alg'] = $key->alg;
        $h['enc'] = self::ENC;
        $h64 = Crypto::base64UrlEncode((string) json_encode($h, JSON_UNESCAPED_SLASHES));
        [$cek, $encKey] = $key->newContentKey();
        $iv = random_bytes(12);
        $ct = openssl_encrypt($plaintext, 'aes-256-gcm', $cek, OPENSSL_RAW_DATA, $iv, $tag, $h64, 16);
        if ($ct === false) {
            throw new JwtException('encryption failed');
        }

        return implode('.', [$h64, Crypto::base64UrlEncode($encKey), Crypto::base64UrlEncode($iv), Crypto::base64UrlEncode($ct), Crypto::base64UrlEncode($tag)]);
    }

    public static function looksLikeJwe(string $token): bool
    {
        return substr_count($token, '.') === 4 && str_starts_with($token, 'eyJ');
    }

    /**
     * Authenticated decryption. Keys are chosen by kid and must match the header alg.
     *
     * @param list<EncryptionKey> $keys
     * @return array{0: array<string, mixed>, 1: string} [protected header, plaintext]
     * @throws JwtException
     */
    public static function decrypt(string $jwe, array $keys): array
    {
        $parts = explode('.', $jwe);
        if (count($parts) !== 5) {
            throw new JwtException('not a JWE');
        }
        [$h64, $k64, $iv64, $ct64, $tag64] = $parts;
        $hj = Crypto::base64UrlDecode($h64);
        $header = $hj !== null ? json_decode($hj, true) : null;
        $encKey = Crypto::base64UrlDecode($k64);
        $iv = Crypto::base64UrlDecode($iv64);
        $ct = Crypto::base64UrlDecode($ct64);
        $tag = Crypto::base64UrlDecode($tag64);
        if (!is_array($header) || $encKey === null || $iv === null || $ct === null || $tag === null) {
            throw new JwtException('malformed');
        }
        $alg = $header['alg'] ?? null;
        if (!in_array($alg, [EncryptionKey::RSA_OAEP_256, EncryptionKey::DIR], true)) {
            throw new JwtException('unsupported alg');
        }
        if (($header['enc'] ?? null) !== self::ENC) {
            throw new JwtException('unsupported enc');
        }
        if (isset($header['zip']) || isset($header['crit'])) {
            throw new JwtException('unsupported header parameter');
        }
        if (strlen($iv) !== 12 || strlen($tag) !== 16) {
            throw new JwtException('malformed');
        }
        $key = null;
        foreach ($keys as $k) {
            if ($k->kid === ($header['kid'] ?? null) && $k->alg === $alg && $k->canDecrypt()) {
                $key = $k;
                break;
            }
        }
        if ($key === null) {
            throw new JwtException('unknown kid');
        }
        // RFC 7516 §11.5: an unrecoverable CEK continues with a random one, so every failure ends at the GCM tag
        $cek = $key->contentKey($encKey) ?? random_bytes(32);
        $plain = openssl_decrypt($ct, 'aes-256-gcm', $cek, OPENSSL_RAW_DATA, $iv, $tag, $h64);
        if ($plain === false) {
            throw new JwtException('decryption failed');
        }

        return [$header, $plain];
    }
}
