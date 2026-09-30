<?php

declare(strict_types=1);

namespace Loongs\OAuth\Authorization;

use Loongs\OAuth\AuthorizationServer;
use Loongs\OAuth\Http\OAuthRequest;

/**
 * The pluggable user-authentication + consent step. The host app decides how users log in
 * (session cookie, SSO, password form …) and how consent is asked. Use
 * $server->hasConsent($userId, $authRequest) to skip the consent screen for remembered grants.
 */
interface AuthorizationHandlerInterface
{
    public function handle(AuthorizationRequest $authRequest, OAuthRequest $request, AuthorizationServer $server): AuthorizationDecision;
}
