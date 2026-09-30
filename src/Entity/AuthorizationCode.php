<?php

declare(strict_types=1);

namespace Loongs\OAuth\Entity;

/** A stored authorization code (only its hash is kept). familyId links every token issued from it. */
final readonly class AuthorizationCode
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $codeHash,
        public string $clientId,
        public string $userId,
        public string $redirectUri,
        public bool $redirectUriProvided,
        public array $scopes,
        public string $codeChallenge,
        public string $codeChallengeMethod,
        public string $familyId,
        public int $expiresAt,
        public ?int $usedAt = null,
        public int $createdAt = 0,
    ) {
    }

    public function isExpired(int $now): bool
    {
        return $now >= $this->expiresAt;
    }
}
