<?php

declare(strict_types=1);

namespace Loongs\OAuth\Entity;

/** A user's remembered consent for a client. */
final readonly class Consent
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $userId,
        public string $clientId,
        public array $scopes,
        public int $grantedAt,
    ) {
    }

    /** @param list<string> $scopes */
    public function covers(array $scopes): bool
    {
        return array_diff($scopes, $this->scopes) === [];
    }
}
