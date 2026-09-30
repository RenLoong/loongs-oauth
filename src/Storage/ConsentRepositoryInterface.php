<?php

declare(strict_types=1);

namespace Loongs\OAuth\Storage;

use Loongs\OAuth\Entity\Consent;

interface ConsentRepositoryInterface
{
    public function findConsent(string $userId, string $clientId): ?Consent;

    public function saveConsent(Consent $consent): void;

    public function revokeConsent(string $userId, string $clientId): void;
}
