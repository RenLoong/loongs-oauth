<?php

declare(strict_types=1);

namespace Loongs\OAuth;

/** A validated access token (resource server) — set as request attribute "oauth" by BearerMiddleware. */
final readonly class TokenInfo
{
    /** @param list<string> $scopes @param array<string, mixed> $claims JWT claims (empty for opaque) */
    public function __construct(
        public string $clientId,
        public ?string $userId,
        public array $scopes,
        public int $expiresAt,
        public int $issuedAt,
        public string $jti,
        public string $format,
        public array $claims = [],
    ) {
    }

    public function hasScope(string ...$scopes): bool
    {
        return array_diff($scopes, $this->scopes) === [];
    }

    /** Subject: the user, or the client itself for client_credentials. */
    public function subject(): string
    {
        return $this->userId ?? $this->clientId;
    }
}
