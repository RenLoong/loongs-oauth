<?php

declare(strict_types=1);

namespace Loongs\OAuth\Grant;

/**
 * Outcome of an extension grant: the resource owner the tokens are issued to.
 *
 * $scopes null = the request's `scope` parameter (or the default scopes when absent); either way
 * the scopes are checked against the client and the server exactly like the other grants.
 * $refreshToken: also issue a refresh token (only if the client may use refresh_token); refresh
 * tokens from an extension grant rotate and are reuse-detected like any other.
 * $extra: additional members of the token response (standard members cannot be overridden).
 */
final readonly class ExtensionGrantResult
{
    /**
     * @param list<string>|null $scopes
     * @param array<string, scalar|array<mixed>|null> $extra
     */
    public function __construct(
        public string $userId,
        public ?array $scopes = null,
        public bool $refreshToken = true,
        public array $extra = [],
    ) {
        if ($userId === '') {
            throw new \InvalidArgumentException('An extension grant must resolve to a non-empty user id.');
        }
    }
}
