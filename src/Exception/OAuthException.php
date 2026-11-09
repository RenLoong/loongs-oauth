<?php

declare(strict_types=1);

namespace Loongs\OAuth\Exception;

use Loongs\OAuth\Http\OAuthResponse;

/**
 * An OAuth error: RFC 6749 §5.2 (token endpoint JSON), §4.1.2.1 (authorization redirect), RFC 6750 §3
 * (resource server WWW-Authenticate). error_description never contains secrets or token values.
 *
 * For resource-server invalid_token failures, $reason distinguishes client handling:
 *   expired  — access token past exp; client may try refresh_token
 *   revoked  — explicitly revoked / family revoked; client should re-login
 *   invalid  — malformed, wrong issuer/audience, unknown, etc.; client should re-login
 */
class OAuthException extends \RuntimeException
{
    public const string REASON_EXPIRED = 'expired';
    public const string REASON_REVOKED = 'revoked';
    public const string REASON_INVALID = 'invalid';

    /** @param array<string, string> $headers */
    public function __construct(
        public readonly string $error,
        public readonly string $description = '',
        public readonly int $status = 400,
        public readonly array $headers = [],
        public readonly ?string $errorUri = null,
        public readonly ?string $reason = null,
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

    /**
     * RFC 6750 invalid_token (401). $reason is expired|revoked|invalid for structured client handling.
     *
     * @param array<string, string> $headers
     */
    public static function invalidToken(string $d, string $reason = self::REASON_INVALID, array $headers = []): self
    {
        return new self('invalid_token', $d, 401, $headers, reason: $reason);
    }

    public function isExpired(): bool
    {
        return $this->reason === self::REASON_EXPIRED;
    }

    public function isRevoked(): bool
    {
        return $this->reason === self::REASON_REVOKED;
    }

    /** @return array{error: string, error_description?: string, error_uri?: string, reason?: string} */
    public function toArray(): array
    {
        $a = ['error' => $this->error];
        if ($this->description !== '') {
            $a['error_description'] = $this->description;
        }
        if ($this->errorUri !== null) {
            $a['error_uri'] = $this->errorUri;
        }
        if ($this->reason !== null && $this->reason !== '') {
            $a['reason'] = $this->reason;
        }

        return $a;
    }

    /** RFC 6749 §5.2 JSON error response (Cache-Control: no-store). */
    public function toResponse(): OAuthResponse
    {
        return OAuthResponse::json($this->toArray(), $this->status, $this->headers);
    }
}
