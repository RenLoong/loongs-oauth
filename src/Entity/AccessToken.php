<?php

declare(strict_types=1);

namespace Loongs\OAuth\Entity;

/**
 * A stored access token. Opaque tokens: tokenHash = hash of the token. JWT tokens (RFC 9068):
 * tokenHash = hash of the jti, so revocation / introspection work for JWTs too.
 */
final readonly class AccessToken
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $tokenHash,
        public string $jti,
        public string $clientId,
        public ?string $userId,
        public array $scopes,
        public string $familyId,
        public int $issuedAt,
        public int $expiresAt,
        public ?int $revokedAt = null,
        public string $format = 'opaque',
    ) {
    }
}
