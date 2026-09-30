<?php

declare(strict_types=1);

namespace Loongs\OAuth\Jwt;

use OpenSSLAsymmetricKey;

/**
 * RSAES-OAEP with SHA-256 and MGF1-SHA-256, empty label (RFC 8017 §7.1) = JOSE "RSA-OAEP-256".
 * PHP 8.4's openssl_public_encrypt() only offers OAEP with SHA-1, so the encoding is done here and
 * openssl performs the raw RSA operation (OPENSSL_NO_PADDING). Decoding is constant-time with a
 * single failure path (no padding oracle).
 */
final class Oaep
{
    private const int HLEN = 32;

    public static function encrypt(string $message, OpenSSLAsymmetricKey $public): string
    {
        $k = self::modulusLength($public);
        $mLen = strlen($message);
        if ($mLen > $k - 2 * self::HLEN - 2) {
            throw new JwtException('message too long for RSA-OAEP-256');
        }
        $lHash = hash('sha256', '', true);
        $db = $lHash . str_repeat("\0", $k - $mLen - 2 * self::HLEN - 2) . "\x01" . $message;
        $seed = random_bytes(self::HLEN);
        $maskedDb = $db ^ self::mgf1($seed, $k - self::HLEN - 1);
        $maskedSeed = $seed ^ self::mgf1($maskedDb, self::HLEN);
        if (!openssl_public_encrypt("\0" . $maskedSeed . $maskedDb, $out, $public, OPENSSL_NO_PADDING)) {
            throw new JwtException('RSA encryption failed');
        }

        return $out;
    }

    /** null on any failure (one indistinguishable path). */
    public static function decrypt(string $ciphertext, OpenSSLAsymmetricKey $private): ?string
    {
        $k = self::modulusLength($private);
        if (strlen($ciphertext) !== $k || !openssl_private_decrypt($ciphertext, $em, $private, OPENSSL_NO_PADDING)) {
            while (openssl_error_string() !== false) {
            }

            return null;
        }
        $em = str_pad($em, $k, "\0", STR_PAD_LEFT);
        $maskedSeed = substr($em, 1, self::HLEN);
        $maskedDb = substr($em, 1 + self::HLEN);
        $seed = $maskedSeed ^ self::mgf1($maskedDb, self::HLEN);
        $db = $maskedDb ^ self::mgf1($seed, $k - self::HLEN - 1);
        $bad = ord($em[0]) | (hash_equals(hash('sha256', '', true), substr($db, 0, self::HLEN)) ? 0 : 1);
        // find the 0x01 separator after the zero padding without data-dependent branches
        $index = 0;
        $found = 0;
        $n = strlen($db);
        for ($i = self::HLEN; $i < $n; $i++) {
            $b = ord($db[$i]);
            $isOne = (($b ^ 1) - 1) >> 31 & 1;       // 1 iff b == 1
            $isZero = ($b - 1) >> 31 & 1;             // 1 iff b == 0
            $take = $isOne & ($found ^ 1);
            $index |= $take * $i;
            $bad |= ($found ^ 1) & ($isOne ^ 1) & ($isZero ^ 1); // non-zero, non-one byte before the separator
            $found |= $isOne;
        }
        $bad |= $found ^ 1;

        return $bad === 0 ? substr($db, $index + 1) : null;
    }

    public static function modulusLength(OpenSSLAsymmetricKey $key): int
    {
        $d = openssl_pkey_get_details($key);
        if ($d === false || $d['type'] !== OPENSSL_KEYTYPE_RSA) {
            throw new JwtException('RSA key required');
        }

        return (int) ceil($d['bits'] / 8);
    }

    private static function mgf1(string $seed, int $len): string
    {
        $t = '';
        for ($c = 0; strlen($t) < $len; $c++) {
            $t .= hash('sha256', $seed . pack('N', $c), true);
        }

        return substr($t, 0, $len);
    }
}
