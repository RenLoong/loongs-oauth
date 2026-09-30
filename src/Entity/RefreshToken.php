<?php

declare(strict_types=1);

namespace Loongs\OAuth\Entity;

/** A stored refresh token. rotatedAt = it was exchanged once (rotation); a second use is reuse. */
final readonly class RefreshToken
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $tokenHash,
        public string $clientId,
        public ?string $userId,
        public array $scopes,
        public string $familyId,
        public int $issuedAt,
        public int $expiresAt,
        public ?int $rotatedAt = null,
        public ?int $revokedAt = null,
    ) {
    }
}
