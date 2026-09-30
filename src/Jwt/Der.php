<?php

declare(strict_types=1);

namespace Loongs\OAuth\Jwt;

/** Minimal DER encoding for public keys (JWK → PEM) and ECDSA signature conversion (DER ↔ JOSE R||S). */
final class Der
{
    public static function length(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $b = ltrim(pack('N', $len), "\0");

        return chr(0x80 | strlen($b)) . $b;
    }

    public static function tlv(int $tag, string $value): string
    {
        return chr($tag) . self::length(strlen($value)) . $value;
    }

    /** Unsigned big-endian integer → DER INTEGER (leading 0x00 when the high bit is set). */
    public static function uint(string $bytes): string
    {
        $bytes = ltrim($bytes, "\0");
        if ($bytes === '' || (ord($bytes[0]) & 0x80)) {
            $bytes = "\0" . $bytes;
        }

        return self::tlv(0x02, $bytes);
    }

    public static function sequence(string ...$items): string
    {
        return self::tlv(0x30, implode('', $items));
    }

    public static function pem(string $der, string $label = 'PUBLIC KEY'): string
    {
        return "-----BEGIN {$label}-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END {$label}-----\n";
    }

    /** RSA SubjectPublicKeyInfo from modulus n and exponent e (raw big-endian bytes). */
    public static function rsaPublicKey(string $n, string $e): string
    {
        $algo = self::sequence(self::tlv(0x06, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"), "\x05\x00");

        return self::pem(self::sequence($algo, self::tlv(0x03, "\0" . self::sequence(self::uint($n), self::uint($e)))));
    }

    /** P-256 SubjectPublicKeyInfo from 32-byte x and y. */
    public static function p256PublicKey(string $x, string $y): string
    {
        $algo = self::sequence(self::tlv(0x06, "\x2a\x86\x48\xce\x3d\x02\x01"), self::tlv(0x06, "\x2a\x86\x48\xce\x3d\x03\x01\x07"));

        return self::pem(self::sequence($algo, self::tlv(0x03, "\0\x04" . $x . $y)));
    }

    /** openssl_sign() ECDSA output (DER SEQUENCE{r, s}) → JOSE R||S, each $size bytes. */
    public static function ecdsaDerToRaw(string $der, int $size = 32): ?string
    {
        $pos = 0;
        if (self::readTag($der, $pos, 0x30) === null) {
            return null;
        }
        $r = self::readTag($der, $pos, 0x02);
        $s = self::readTag($der, $pos, 0x02);
        if ($r === null || $s === null) {
            return null;
        }
        $r = ltrim($r, "\0");
        $s = ltrim($s, "\0");
        if (strlen($r) > $size || strlen($s) > $size) {
            return null;
        }

        return str_pad($r, $size, "\0", STR_PAD_LEFT) . str_pad($s, $size, "\0", STR_PAD_LEFT);
    }

    /** JOSE R||S → DER for openssl_verify(). */
    public static function ecdsaRawToDer(string $raw, int $size = 32): ?string
    {
        if (strlen($raw) !== 2 * $size) {
            return null;
        }

        return self::sequence(self::uint(substr($raw, 0, $size)), self::uint(substr($raw, $size)));
    }

    /** Read one TLV with the expected tag at $pos; for SEQUENCE returns its content and moves inside it. */
    private static function readTag(string $der, int &$pos, int $tag): ?string
    {
        if (!isset($der[$pos + 1]) || ord($der[$pos]) !== $tag) {
            return null;
        }
        $pos++;
        $len = ord($der[$pos++]);
        if ($len & 0x80) {
            $n = $len & 0x7f;
            if ($n < 1 || $n > 2 || !isset($der[$pos + $n - 1])) {
                return null;
            }
            $len = 0;
            for ($i = 0; $i < $n; $i++) {
                $len = ($len << 8) | ord($der[$pos++]);
            }
        }
        if ($pos + $len > strlen($der)) {
            return null;
        }
        $value = substr($der, $pos, $len);
        if ($tag !== 0x30) {
            $pos += $len;
        }

        return $value;
    }
}
