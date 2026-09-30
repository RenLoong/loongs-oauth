<?php

declare(strict_types=1);

namespace Loongs\OAuth\Grant;

use Loongs\OAuth\AuthorizationServer;
use Loongs\OAuth\Entity\Client;
use Loongs\OAuth\Http\OAuthRequest;

/**
 * Handler of an extension grant (RFC 6749 §4.5): the token endpoint authenticated $client, checked
 * that it may use the grant type, and hands over the request. Validate the grant's own parameters
 * and return who the tokens are for, or throw OAuthException (invalid_request / invalid_grant / …),
 * which the token endpoint turns into the RFC 6749 §5.2 error response.
 */
interface ExtensionGrantHandler
{
    public function handle(OAuthRequest $request, Client $client, AuthorizationServer $server): ExtensionGrantResult;
}
