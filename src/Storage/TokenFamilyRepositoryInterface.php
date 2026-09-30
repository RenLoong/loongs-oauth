<?php

declare(strict_types=1);

namespace Loongs\OAuth\Storage;

/**
 * A token family = one authorization grant: the authorization code (or client_credentials call) and
 * every access / refresh token issued from it, across refresh rotations. Revoking the family
 * invalidates all of them — including tokens written after the revocation (concurrent exchanges),
 * because validation checks the family too.
 */
interface TokenFamilyRepositoryInterface
{
    public function revokeFamily(string $familyId, int $now, string $reason): void;

    public function isFamilyRevoked(string $familyId): bool;
}
