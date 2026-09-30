<?php

declare(strict_types=1);

namespace Loongs\OAuth\Storage;

use Loongs\OAuth\Entity\AccessToken;
use Loongs\OAuth\Entity\AuthorizationCode;
use Loongs\OAuth\Entity\Client;
use Loongs\OAuth\Entity\Consent;
use Loongs\OAuth\Entity\RefreshToken;

/**
 * In-process storage for tests and single-process tools. Per-process: Swoole workers do not share it.
 * Check-and-set methods never yield, so they are atomic between coroutines of one process.
 */
final class MemoryStorage implements StorageInterface
{
    /** @var array<string, Client> */
    private array $clients = [];
    /** @var array<string, AuthorizationCode> */
    private array $codes = [];
    /** @var array<string, AccessToken> */
    private array $access = [];
    /** @var array<string, RefreshToken> */
    private array $refresh = [];
    /** @var array<string, int> */
    private array $families = [];
    /** @var array<string, Consent> */
    private array $consents = [];

    public function findClient(string $clientId): ?Client { return $this->clients[$clientId] ?? null; }

    public function saveClient(Client $client): void { $this->clients[$client->id] = $client; }

    public function deleteClient(string $clientId): void { unset($this->clients[$clientId]); }

    public function saveAuthCode(AuthorizationCode $code): void { $this->codes[$code->codeHash] = $code; }

    public function findAuthCode(string $codeHash): ?AuthorizationCode { return $this->codes[$codeHash] ?? null; }

    public function consumeAuthCode(string $codeHash, int $now): bool
    {
        $c = $this->codes[$codeHash] ?? null;
        if ($c === null || $c->usedAt !== null) {
            return false;
        }
        $this->codes[$codeHash] = new AuthorizationCode($c->codeHash, $c->clientId, $c->userId, $c->redirectUri, $c->redirectUriProvided,
            $c->scopes, $c->codeChallenge, $c->codeChallengeMethod, $c->familyId, $c->expiresAt, $now, $c->createdAt);

        return true;
    }

    public function saveAccessToken(AccessToken $token): void { $this->access[$token->tokenHash] = $token; }

    public function findAccessToken(string $tokenHash): ?AccessToken { return $this->access[$tokenHash] ?? null; }

    public function revokeAccessToken(string $tokenHash, int $now): void
    {
        $t = $this->access[$tokenHash] ?? null;
        if ($t !== null && $t->revokedAt === null) {
            $this->access[$tokenHash] = new AccessToken($t->tokenHash, $t->jti, $t->clientId, $t->userId, $t->scopes, $t->familyId, $t->issuedAt, $t->expiresAt, $now, $t->format);
        }
    }

    public function saveRefreshToken(RefreshToken $token): void { $this->refresh[$token->tokenHash] = $token; }

    public function findRefreshToken(string $tokenHash): ?RefreshToken { return $this->refresh[$tokenHash] ?? null; }

    public function rotateRefreshToken(string $tokenHash, int $now): bool
    {
        $t = $this->refresh[$tokenHash] ?? null;
        if ($t === null || $t->rotatedAt !== null || $t->revokedAt !== null) {
            return false;
        }
        $this->refresh[$tokenHash] = new RefreshToken($t->tokenHash, $t->clientId, $t->userId, $t->scopes, $t->familyId, $t->issuedAt, $t->expiresAt, $now, null);

        return true;
    }

    public function revokeRefreshToken(string $tokenHash, int $now): void
    {
        $t = $this->refresh[$tokenHash] ?? null;
        if ($t !== null && $t->revokedAt === null) {
            $this->refresh[$tokenHash] = new RefreshToken($t->tokenHash, $t->clientId, $t->userId, $t->scopes, $t->familyId, $t->issuedAt, $t->expiresAt, $t->rotatedAt, $now);
        }
    }

    public function revokeFamily(string $familyId, int $now, string $reason): void
    {
        $this->families[$familyId] ??= $now;
        foreach ($this->access as $h => $t) {
            if ($t->familyId === $familyId) {
                $this->revokeAccessToken($h, $now);
            }
        }
        foreach ($this->refresh as $h => $t) {
            if ($t->familyId === $familyId) {
                $this->revokeRefreshToken($h, $now);
            }
        }
    }

    public function isFamilyRevoked(string $familyId): bool { return isset($this->families[$familyId]); }

    public function findConsent(string $userId, string $clientId): ?Consent { return $this->consents["{$userId}\0{$clientId}"] ?? null; }

    public function saveConsent(Consent $consent): void { $this->consents["{$consent->userId}\0{$consent->clientId}"] = $consent; }

    public function revokeConsent(string $userId, string $clientId): void { unset($this->consents["{$userId}\0{$clientId}"]); }

    public function purgeExpired(int $now): int
    {
        $n = 0;
        foreach (['codes', 'access', 'refresh'] as $bag) {
            foreach ($this->{$bag} as $k => $v) {
                if ($v->expiresAt <= $now) {
                    unset($this->{$bag}[$k]);
                    $n++;
                }
            }
        }

        return $n;
    }
}
