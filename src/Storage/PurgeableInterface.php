<?php

declare(strict_types=1);

namespace Loongs\OAuth\Storage;

interface PurgeableInterface
{
    /** Delete expired codes / tokens (run from a crontab process). Returns rows removed. */
    public function purgeExpired(int $now): int;
}
