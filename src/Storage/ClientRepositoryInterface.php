<?php

declare(strict_types=1);

namespace Loongs\OAuth\Storage;

use Loongs\OAuth\Entity\Client;

interface ClientRepositoryInterface
{
    public function findClient(string $clientId): ?Client;

    /** Insert or replace. */
    public function saveClient(Client $client): void;

    public function deleteClient(string $clientId): void;
}
