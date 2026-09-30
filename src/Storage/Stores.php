<?php

declare(strict_types=1);

namespace Loongs\OAuth\Storage;

/**
 * The repositories the servers use. One object implementing all of them (MemoryStorage, OrmStorage):
 * Stores::of($storage). Mixed: clients / consents in MySQL, codes and tokens in Redis:
 *   new Stores(clients: $orm, consents: $orm, codes: $cache, accessTokens: $cache, refreshTokens: $cache, families: $cache)
 */
final readonly class Stores
{
    public function __construct(
        public ClientRepositoryInterface $clients,
        public AuthCodeRepositoryInterface $codes,
        public AccessTokenRepositoryInterface $accessTokens,
        public RefreshTokenRepositoryInterface $refreshTokens,
        public TokenFamilyRepositoryInterface $families,
        public ConsentRepositoryInterface $consents,
    ) {
    }

    public static function of(ClientRepositoryInterface&AuthCodeRepositoryInterface&AccessTokenRepositoryInterface&RefreshTokenRepositoryInterface&TokenFamilyRepositoryInterface&ConsentRepositoryInterface $s): self
    {
        return new self($s, $s, $s, $s, $s, $s);
    }
}
