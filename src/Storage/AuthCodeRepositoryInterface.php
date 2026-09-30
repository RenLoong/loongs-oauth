<?php

declare(strict_types=1);

namespace Loongs\OAuth\Storage;

use Loongs\OAuth\Entity\AuthorizationCode;

interface AuthCodeRepositoryInterface
{
    public function saveAuthCode(AuthorizationCode $code): void;

    /** The code (used or not) — used codes must stay findable until they expire, for reuse detection. */
    public function findAuthCode(string $codeHash): ?AuthorizationCode;

    /**
     * Atomically mark the code used. true for exactly one caller, even under concurrency
     * (UPDATE … WHERE used_at IS NULL / SET NX); false when it was already used or does not exist.
     */
    public function consumeAuthCode(string $codeHash, int $now): bool;
}
