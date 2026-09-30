<?php

declare(strict_types=1);

namespace Loongs\OAuth\Jwt;

use Loongs\OAuth\Support\Crypto;
use OpenSSLAsymmetricKey;

/**
 * A JWE key-management key for access tokens:
 *   RSA-OAEP-256 — the authorization server needs the public key, resource servers the private key;
 *   dir          — one shared 256-bit secret used directly as the A256GCM content key.
 * Never published: JWKS / metadata only carry signing keys. var_dump()/print_r() hide the material.
 */
final class EncryptionKey
{
    public const string RSA_OAEP_256 = 'RSA-OAEP-256';
    public const string DIR = 'dir';

    public readonly string $kid;

    private function __construct(
        public readonly string $alg,
        private readonly ?OpenSSLAsymmetricKey $public,
        private readonly ?OpenSSLAsymmetricKey $private,
        #[\SensitiveParameter] private readonly ?string $secret,
        ?string $kid,
    ) {
        $this->kid = $kid ?? match ($alg) {
            self::DIR => 'dir-' . substr(Crypto::base64UrlEncode(hash_hmac('sha256', 'loongs-oauth/kid', (string) $secret, true)), 0, 16),
            default => 'enc-' . SigningKey::thumbprint(self::rsaJwk((array) openssl_pkey_get_details($public ?? $private))),
        };
    }

    public static function generateRsa(int $bits = 2048, ?string $kid = null): self
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => max(2048, $bits)]);
        if ($key === false) {
            throw new \RuntimeException('openssl_pkey_new failed');
        }

        return self::rsa($key, $kid);
    }

    /** Private RSA key (encrypt + decrypt). */
    public static function fromRsaPrivatePem(#[\SensitiveParameter] string $pem, ?string $kid = null, #[\SensitiveParameter] ?string $passphrase = null): self
    {
        $key = openssl_pkey_get_private($pem, $passphrase);
        if ($key === false) {
            throw new \InvalidArgumentException('Invalid RSA private key PEM.');
        }

        return self::rsa($key, $kid);
    }

    /** Public RSA key only: this side can encrypt (authorization server) but not decrypt. */
    public static function fromRsaPublicPem(string $pem, ?string $kid = null): self
    {
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new \InvalidArgumentException('Invalid RSA public key PEM.');
        }
        self::assertRsa($key);

        return new self(self::RSA_OAEP_256, $key, null, null, $kid);
    }

    /** Shared symmetric key for alg=dir, exactly 32 bytes (raw). */
    public static function direct(#[\SensitiveParameter] string $secret, ?string $kid = null): self
    {
        if (strlen($secret) !== 32) {
            throw new \InvalidArgumentException('dir + A256GCM needs a 32-byte key.');
        }

        return new self(self::DIR, null, null, $secret, $kid);
    }

    public static function generateDirect(?string $kid = null): self
    {
        return self::direct(random_bytes(32), $kid);
    }

    private static function rsa(OpenSSLAsymmetricKey $key, ?string $kid): self
    {
        self::assertRsa($key);
        $pub = openssl_pkey_get_public((string) openssl_pkey_get_details($key)['key']);

        return new self(self::RSA_OAEP_256, $pub ?: null, $key, null, $kid);
    }

    private static function assertRsa(OpenSSLAsymmetricKey $key): void
    {
        $d = openssl_pkey_get_details($key);
        if ($d === false || $d['type'] !== OPENSSL_KEYTYPE_RSA || $d['bits'] < 2048) {
            throw new \InvalidArgumentException('RSA-OAEP-256 needs an RSA key of at least 2048 bits.');
        }
    }

    public function canDecrypt(): bool
    {
        return $this->alg === self::DIR || $this->private !== null;
    }

    public function canEncrypt(): bool
    {
        return $this->alg === self::DIR || $this->public !== null;
    }

    /** @internal content-encryption key for a new token: [cek, encrypted_key] */
    public function newContentKey(): array
    {
        if ($this->alg === self::DIR) {
            return [(string) $this->secret, ''];
        }
        $cek = random_bytes(32);

        return [$cek, Oaep::encrypt($cek, $this->public ?? throw new JwtException('no public key'))];
    }

    /** @internal CEK from the JWE encrypted key; null when it cannot be recovered. */
    public function contentKey(string $encryptedKey): ?string
    {
        if ($this->alg === self::DIR) {
            return $encryptedKey === '' ? $this->secret : null;
        }
        if ($this->private === null) {
            return null;
        }
        $cek = Oaep::decrypt($encryptedKey, $this->private);

        return $cek !== null && strlen($cek) === 32 ? $cek : null;
    }

    public function publicPem(): ?string
    {
        return $this->public !== null ? (string) openssl_pkey_get_details($this->public)['key'] : null;
    }

    public function privatePem(): ?string
    {
        if ($this->private === null) {
            return null;
        }
        openssl_pkey_export($this->private, $pem);

        return (string) $pem;
    }

    /** Raw dir secret (for distributing to resource servers through your secret store). */
    public function secret(): ?string
    {
        return $this->secret;
    }

    /** @param array<string, mixed> $d */
    private static function rsaJwk(array $d): array
    {
        return ['kty' => 'RSA', 'n' => Crypto::base64UrlEncode(ltrim($d['rsa']['n'], "\0")), 'e' => Crypto::base64UrlEncode(ltrim($d['rsa']['e'], "\0"))];
    }

    public function __debugInfo(): array
    {
        return ['alg' => $this->alg, 'kid' => $this->kid, 'decrypt' => $this->canDecrypt()];
    }

    public function __serialize(): array
    {
        throw new \LogicException('EncryptionKey is not serializable.');
    }
}
