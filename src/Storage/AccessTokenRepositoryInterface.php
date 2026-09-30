<?php

declare(strict_types=1);

namespace Loongs\OAuth\Storage;

use Loongs\OAuth\Entity\AccessToken;

interface AccessTokenRepositoryInterface
{
    public function saveAccessToken(AccessToken $token): void;

    public function findAccessToken(string $tokenHash): ?AccessToken;

    public function revokeAccessToken(string $tokenHash, int $now): void;
}
