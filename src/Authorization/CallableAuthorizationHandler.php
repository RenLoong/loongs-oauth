<?php

declare(strict_types=1);

namespace Loongs\OAuth\Authorization;

use Closure;
use Loongs\OAuth\AuthorizationServer;
use Loongs\OAuth\Http\OAuthRequest;

/** Closure(AuthorizationRequest, OAuthRequest, AuthorizationServer): AuthorizationDecision as a handler. */
final readonly class CallableAuthorizationHandler implements AuthorizationHandlerInterface
{
    public function __construct(private Closure $fn)
    {
    }

    public function handle(AuthorizationRequest $authRequest, OAuthRequest $request, AuthorizationServer $server): AuthorizationDecision
    {
        return ($this->fn)($authRequest, $request, $server);
    }
}
