<?php

declare(strict_types=1);

namespace Loongs\OAuth\Storage;

/** Everything in one backend (MemoryStorage, OrmStorage). */
interface StorageInterface extends ClientRepositoryInterface, AuthCodeRepositoryInterface, AccessTokenRepositoryInterface,
    RefreshTokenRepositoryInterface, TokenFamilyRepositoryInterface, ConsentRepositoryInterface, PurgeableInterface
{
}
