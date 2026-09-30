<?php

declare(strict_types=1);

namespace Loongs\OAuth\Storage;

use Loongs\Cache\Repository;
use Loongs\OAuth\Entity\AccessToken;
use Loongs\OAuth\Entity\AuthorizationCode;
use Loongs\OAuth\Entity\RefreshToken;

/**
 * Codes, access / refresh tokens and family revocations in a loongs/cache store (Redis in
 * production). Clients and consents stay in a durable store (OrmStorage):
 *
 *   $cache = new CacheTokenStorage(new Repository(new RedisStore($runner, 'loong:oauth:t1:')));
 *   $stores = new Stores(clients: $orm, codes: $cache, accessTokens: $cache, refreshTokens: $cache, families: $cache, consents: $orm);
 *
 * Entries expire with the code / token. Single-use and rotation are Repository::add() (Redis SET NX)
 * marker keys, so exactly one of several concurrent exchanges wins, across processes. Use one key
 * prefix per tenant.
 */
final readonly class CacheTokenStorage implements AuthCodeRepositoryInterface, AccessTokenRepositoryInterface,
    RefreshTokenRepositoryInterface, TokenFamilyRepositoryInterface, PurgeableInterface
{
    /** @param int $familyTtl how long a family revocation is remembered (>= the refresh-token TTL) */
    public function __construct(
        private Repository $cache,
        private string $prefix = 'oauth.',
        private int $familyTtl = 2_678_400,
    ) {
    }

    private function ttl(int $expiresAt): int
    {
        return max(1, $expiresAt - time());
    }

    public function saveAuthCode(AuthorizationCode $code): void
    {
        // used codes must stay visible for reuse detection until they expire
        $this->cache->set($this->prefix . 'code.' . $code->codeHash, get_object_vars($code), $this->ttl($code->expiresAt) + 60);
    }

    public function findAuthCode(string $codeHash): ?AuthorizationCode
    {
        $a = $this->cache->get($this->prefix . 'code.' . $codeHash);
        if (!is_array($a)) {
            return null;
        }
        $used = $this->cache->get($this->prefix . 'code_used.' . $codeHash);
        $a['usedAt'] = is_int($used) ? $used : null;

        return new AuthorizationCode(...$a);
    }

    public function consumeAuthCode(string $codeHash, int $now): bool
    {
        $code = $this->cache->get($this->prefix . 'code.' . $codeHash);

        return is_array($code) && $this->cache->add($this->prefix . 'code_used.' . $codeHash, $now, $this->ttl((int) $code['expiresAt']) + 60);
    }

    public function saveAccessToken(AccessToken $token): void
    {
        $this->cache->set($this->prefix . 'at.' . $token->tokenHash, get_object_vars($token), $this->ttl($token->expiresAt));
    }

    public function findAccessToken(string $tokenHash): ?AccessToken
    {
        $a = $this->cache->get($this->prefix . 'at.' . $tokenHash);
        if (!is_array($a)) {
            return null;
        }
        $rev = $this->cache->get($this->prefix . 'at_revoked.' . $tokenHash);
        if (is_int($rev)) {
            $a['revokedAt'] = $rev;
        }

        return new AccessToken(...$a);
    }

    public function revokeAccessToken(string $tokenHash, int $now): void
    {
        $a = $this->cache->get($this->prefix . 'at.' . $tokenHash);
        if (is_array($a)) {
            $this->cache->add($this->prefix . 'at_revoked.' . $tokenHash, $now, $this->ttl((int) $a['expiresAt']));
        }
    }

    public function saveRefreshToken(RefreshToken $token): void
    {
        $this->cache->set($this->prefix . 'rt.' . $token->tokenHash, get_object_vars($token), $this->ttl($token->expiresAt));
    }

    public function findRefreshToken(string $tokenHash): ?RefreshToken
    {
        $a = $this->cache->get($this->prefix . 'rt.' . $tokenHash);
        if (!is_array($a)) {
            return null;
        }
        foreach (['rotatedAt' => 'rt_rotated.', 'revokedAt' => 'rt_revoked.'] as $field => $k) {
            $v = $this->cache->get($this->prefix . $k . $tokenHash);
            if (is_int($v)) {
                $a[$field] = $v;
            }
        }

        return new RefreshToken(...$a);
    }

    public function rotateRefreshToken(string $tokenHash, int $now): bool
    {
        $t = $this->findRefreshToken($tokenHash);

        return $t !== null && $t->revokedAt === null && $this->cache->add($this->prefix . 'rt_rotated.' . $tokenHash, $now, $this->ttl($t->expiresAt));
    }

    public function revokeRefreshToken(string $tokenHash, int $now): void
    {
        $a = $this->cache->get($this->prefix . 'rt.' . $tokenHash);
        if (is_array($a)) {
            $this->cache->add($this->prefix . 'rt_revoked.' . $tokenHash, $now, $this->ttl((int) $a['expiresAt']));
        }
    }

    /** Tokens are not enumerated: validation consults the family marker (see TokenFamilyRepositoryInterface). */
    public function revokeFamily(string $familyId, int $now, string $reason): void
    {
        $this->cache->add($this->prefix . 'family_revoked.' . $familyId, $now, $this->familyTtl);
    }

    public function isFamilyRevoked(string $familyId): bool
    {
        return $this->cache->has($this->prefix . 'family_revoked.' . $familyId);
    }

    /** Entries carry their own TTL. */
    public function purgeExpired(int $now): int
    {
        return 0;
    }
}
