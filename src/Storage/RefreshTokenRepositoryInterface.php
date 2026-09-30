<?php

declare(strict_types=1);

namespace Loongs\OAuth\Storage;

use Loongs\OAuth\Entity\RefreshToken;

interface RefreshTokenRepositoryInterface
{
    public function saveRefreshToken(RefreshToken $token): void;

    public function findRefreshToken(string $tokenHash): ?RefreshToken;

    /** Atomically mark the token rotated (exchanged). true for exactly one caller; false = already used / revoked. */
    public function rotateRefreshToken(string $tokenHash, int $now): bool;

    public function revokeRefreshToken(string $tokenHash, int $now): void;
}
