<?php

declare(strict_types=1);

namespace Loongs\OAuth\Authorization;

use Loongs\OAuth\Http\OAuthResponse;

/** What the host application decided for an authorization request. */
final readonly class AuthorizationDecision
{
    /** @param list<string>|null $scopes */
    private function __construct(
        public string $kind,
        public ?string $userId = null,
        public ?array $scopes = null,
        public bool $remember = false,
        public ?OAuthResponse $response = null,
    ) {
    }

    /**
     * The user is authenticated and consented. $scopes may narrow the requested scopes;
     * $remember stores the consent so the next request for the same scopes can skip the screen.
     *
     * @param list<string>|null $scopes
     */
    public static function approve(string $userId, ?array $scopes = null, bool $remember = false): self
    {
        return new self('approve', $userId, $scopes, $remember);
    }

    /** The user refused → access_denied sent to the client. */
    public static function deny(): self
    {
        return new self('deny');
    }

    /** Not decided yet: send this response (login form, consent screen, redirect to the app's login). */
    public static function respond(OAuthResponse $response): self
    {
        return new self('respond', response: $response);
    }
}
