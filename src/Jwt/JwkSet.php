<?php

declare(strict_types=1);

namespace Loongs\OAuth\Jwt;

use Loongs\OAuth\Support\Crypto;

/**
 * Public verification keys by kid — from our own SigningKeys (authorization server) or from a JWKS
 * document fetched from jwks_uri (a separate resource server). JWKs become PEM through a small DER
 * encoder, then openssl_verify() does the maths.
 */
final class JwkSet
{
    /** @var array<string, array{alg: string, pem: string, jwk: array<string, mixed>}> */
    private array $keys = [];

    public static function fromSigningKeys(SigningKey ...$keys): self
    {
        $set = new self();
        foreach ($keys as $k) {
            $set->add($k->publicJwk());
        }

        return $set;
    }

    /** @param array{keys?: list<array<string, mixed>>}|string $jwks JWKS array or JSON */
    public static function fromJwks(array|string $jwks): self
    {
        $doc = is_string($jwks) ? json_decode($jwks, true) : $jwks;
        if (!is_array($doc) || !isset($doc['keys']) || !is_array($doc['keys'])) {
            throw new \InvalidArgumentException('Not a JWKS document.');
        }
        $set = new self();
        foreach ($doc['keys'] as $jwk) {
            if (is_array($jwk) && ($jwk['use'] ?? 'sig') === 'sig') {
                $set->add($jwk);
            }
        }

        return $set;
    }

    /** @param array<string, mixed> $jwk */
    public function add(array $jwk): void
    {
        $kty = $jwk['kty'] ?? null;
        if ($kty === 'RSA') {
            $n = Crypto::base64UrlDecode((string) ($jwk['n'] ?? ''));
            $e = Crypto::base64UrlDecode((string) ($jwk['e'] ?? ''));
            if ($n === null || $e === null || strlen(ltrim($n, "\0")) < 256) {
                throw new \InvalidArgumentException('Bad RSA JWK (2048-bit minimum).');
            }
            $pem = Der::rsaPublicKey($n, $e);
            $alg = 'RS256';
        } elseif ($kty === 'EC' && ($jwk['crv'] ?? null) === 'P-256') {
            $x = Crypto::base64UrlDecode((string) ($jwk['x'] ?? ''));
            $y = Crypto::base64UrlDecode((string) ($jwk['y'] ?? ''));
            if ($x === null || $y === null || strlen($x) !== 32 || strlen($y) !== 32) {
                throw new \InvalidArgumentException('Bad P-256 JWK.');
            }
            $pem = Der::p256PublicKey($x, $y);
            $alg = 'ES256';
        } else {
            throw new \InvalidArgumentException('Unsupported JWK (RSA or EC P-256 only).');
        }
        if (isset($jwk['alg']) && $jwk['alg'] !== $alg) {
            throw new \InvalidArgumentException('JWK alg does not match its key type.');
        }
        if (openssl_pkey_get_public($pem) === false) {
            throw new \InvalidArgumentException('JWK is not a valid public key.');
        }
        $kid = (string) ($jwk['kid'] ?? SigningKey::thumbprint($jwk));
        $this->keys[$kid] = ['alg' => $alg, 'pem' => $pem, 'jwk' => $jwk + ['kid' => $kid, 'alg' => $alg, 'use' => 'sig']];
    }

    /** @return array{alg: string, pem: string, jwk: array<string, mixed>}|null */
    public function get(string $kid): ?array
    {
        return $this->keys[$kid] ?? null;
    }

    /** @return array{keys: list<array<string, mixed>>} the JWKS document served at jwks_uri */
    public function toArray(): array
    {
        return ['keys' => array_values(array_map(static fn (array $k): array => $k['jwk'], $this->keys))];
    }
}
