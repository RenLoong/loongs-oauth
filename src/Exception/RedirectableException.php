<?php

declare(strict_types=1);

namespace Loongs\OAuth\Exception;

/**
 * Authorization-endpoint error raised after client_id and redirect_uri were validated: it is sent to
 * the client's redirect_uri (RFC 6749 §4.1.2.1) together with state and iss (RFC 9207).
 */
final class RedirectableException extends OAuthException
{
    public function __construct(
        OAuthException $e,
        public readonly string $redirectUri,
        public readonly ?string $state,
    ) {
        parent::__construct($e->error, $e->description, 302, [], $e->errorUri);
    }
}
