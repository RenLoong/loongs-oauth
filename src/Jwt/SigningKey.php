<?php

declare(strict_types=1);

namespace Loongs\OAuth\Jwt;

use Loongs\OAuth\Support\Crypto;
use OpenSSLAsymmetricKey;

/**
 * A private signing key for JWT access tokens: RS256 (RSA >= 2048 bits) or ES256 (P-256).
 * kid defaults to the RFC 7638 JWK thumbprint of the public key.
 */
final readonly class SigningKey
{
    public const array ALGORITHMS = ['RS256', 'ES256'];

    public string $kid;

    private function __construct(
        private OpenSSLAsymmetricKey $key,
        public string $alg,
        ?string $kid,
    ) {
        if (!in_array($alg, self::ALGORITHMS, true)) {
            throw new \InvalidArgumentException("Unsupported JWT algorithm [{$alg}] (RS256 / ES256).");
        }
        $d = openssl_pkey_get_details($key);
        if ($d === false) {
            throw new \InvalidArgumentException('Unreadable private key.');
        }
        if ($alg === 'RS256' && ($d['type'] !== OPENSSL_KEYTYPE_RSA || $d['bits'] < 2048)) {
            throw new \InvalidArgumentException('RS256 needs an RSA key of at least 2048 bits.');
        }
        if ($alg === 'ES256' && ($d['type'] !== OPENSSL_KEYTYPE_EC || ($d['ec']['curve_name'] ?? '') !== 'prime256v1')) {
            throw new \InvalidArgumentException('ES256 needs a P-256 (prime256v1) EC key.');
        }
        $this->kid = $kid ?? self::thumbprint(self::jwkFromDetails($d));
    }

    public static function generate(string $alg = 'ES256', ?string $kid = null): self
    {
        $opts = $alg === 'RS256'
            ? ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]
            : ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'];
        $key = openssl_pkey_new($opts);
        if ($key === false) {
            throw new \RuntimeException('openssl_pkey_new failed: ' . (openssl_error_string() ?: 'unknown'));
        }

        return new self($key, $alg, $kid);
    }

    public static function fromPem(string $privatePem, string $alg, ?string $kid = null, ?string $passphrase = null): self
    {
        $key = openssl_pkey_get_private($privatePem, $passphrase);
        if ($key === false) {
            throw new \InvalidArgumentException('Invalid private key PEM.');
        }

        return new self($key, $alg, $kid);
    }

    public function toPem(): string
    {
        openssl_pkey_export($this->key, $pem);

        return (string) $pem;
    }

    public function sign(string $input): string
    {
        if (!openssl_sign($input, $sig, $this->key, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('openssl_sign failed.');
        }
        if ($this->alg === 'ES256') {
            $sig = Der::ecdsaDerToRaw($sig) ?? throw new \RuntimeException('Bad ECDSA signature encoding.');
        }

        return $sig;
    }

    /** Public JWK (kty, use, alg, kid + n/e or crv/x/y). */
    public function publicJwk(): array
    {
        $d = openssl_pkey_get_details($this->key);

        return self::jwkFromDetails((array) $d) + ['use' => 'sig', 'alg' => $this->alg, 'kid' => $this->kid];
    }

    /** @param array<string, mixed> $d openssl_pkey_get_details() */
    private static function jwkFromDetails(array $d): array
    {
        if ($d['type'] === OPENSSL_KEYTYPE_RSA) {
            return ['kty' => 'RSA', 'n' => Crypto::base64UrlEncode(ltrim($d['rsa']['n'], "\0")), 'e' => Crypto::base64UrlEncode(ltrim($d['rsa']['e'], "\0"))];
        }

        return ['kty' => 'EC', 'crv' => 'P-256',
            'x' => Crypto::base64UrlEncode(str_pad($d['ec']['x'], 32, "\0", STR_PAD_LEFT)),
            'y' => Crypto::base64UrlEncode(str_pad($d['ec']['y'], 32, "\0", STR_PAD_LEFT))];
    }

    /** RFC 7638 thumbprint over the required members in lexicographic order. */
    public static function thumbprint(array $jwk): string
    {
        $req = $jwk['kty'] === 'RSA' ? ['e' => $jwk['e'], 'kty' => 'RSA', 'n' => $jwk['n']]
            : ['crv' => $jwk['crv'], 'kty' => 'EC', 'x' => $jwk['x'], 'y' => $jwk['y']];

        return Crypto::base64UrlEncode(hash('sha256', (string) json_encode($req, JSON_UNESCAPED_SLASHES), true));
    }
}
