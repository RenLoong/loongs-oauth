<?php

declare(strict_types=1);

namespace Loongs\OAuth\Exception;

use Loongs\OAuth\Http\OAuthResponse;

/**
 * An OAuth error: RFC 6749 §5.2 (token endpoint JSON), §4.1.2.1 (authorization redirect), RFC 6750 §3
 * (resource server WWW-Authenticate). error_description never contains secrets or token values.
 */
class OAuthException extends \RuntimeException
{
    /** @param array<string, string> $headers */
    public function __construct(
        public readonly string $error,
        public readonly string $description = '',
        public readonly int $status = 400,
        public readonly array $headers = [],
        public readonly ?string $errorUri = null,
    ) {
        parent::__construct($description !== '' ? "{$error}: {$description}" : $error);
    }

    public static function invalidRequest(string $d): self { return new self('invalid_request', $d); }

    /** @param array<string, string> $headers */
    public static function invalidClient(string $d, array $headers = []): self { return new self('invalid_client', $d, 401, $headers); }

    public static function invalidGrant(string $d): self { return new self('invalid_grant', $d); }

    public static function unauthorizedClient(string $d): self { return new self('unauthorized_client', $d); }

    public static function unsupportedGrantType(string $d): self { return new self('unsupported_grant_type', $d); }

    public static function unsupportedResponseType(string $d): self { return new self('unsupported_response_type', $d); }

    public static function invalidScope(string $d): self { return new self('invalid_scope', $d); }

    public static function accessDenied(string $d): self { return new self('access_denied', $d, 403); }

    public static function unsupportedTokenType(string $d): self { return new self('unsupported_token_type', $d); }

    public static function serverError(string $d): self { return new self('server_error', $d, 500); }

    /** @return array{error: string, error_description?: string, error_uri?: string} */
    public function toArray(): array
    {
        $a = ['error' => $this->error];
        if ($this->description !== '') {
            $a['error_description'] = $this->description;
        }
        if ($this->errorUri !== null) {
            $a['error_uri'] = $this->errorUri;
        }

        return $a;
    }

    /** RFC 6749 §5.2 JSON error response (Cache-Control: no-store). */
    public function toResponse(): OAuthResponse
    {
        return OAuthResponse::json($this->toArray(), $this->status, $this->headers);
    }
}
