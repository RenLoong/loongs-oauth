<?php

declare(strict_types=1);

namespace Loongs\OAuth\Http;

/**
 * Framework-neutral HTTP request as seen by the OAuth endpoints: method, lower-cased headers, query
 * parameters and form body parameters. Build it with fromArrays(), fromGlobals() or
 * Framework\Bridge::request() (loongs/framework).
 */
final readonly class OAuthRequest
{
    /** @var array<string, string> lower-cased header names */
    public array $headers;

    /**
     * @param array<string, string> $headers
     * @param array<string, mixed> $query
     * @param array<string, mixed> $post  parsed application/x-www-form-urlencoded body
     */
    public function __construct(
        public string $method,
        array $headers = [],
        public array $query = [],
        public array $post = [],
        public string $body = '',
    ) {
        $h = [];
        foreach ($headers as $k => $v) {
            $h[strtolower((string) $k)] = (string) $v;
        }
        $this->headers = $h;
    }

    /**
     * @param array<string, string> $headers
     * @param array<string, mixed> $query
     * @param array<string, mixed> $post
     */
    public static function fromArrays(string $method, array $headers = [], array $query = [], array $post = [], string $body = ''): self
    {
        return new self(strtoupper($method), $headers, $query, $post, $body);
    }

    public static function fromGlobals(): self
    {
        $headers = [];
        foreach ($_SERVER as $k => $v) {
            if (str_starts_with((string) $k, 'HTTP_')) {
                $headers[str_replace('_', '-', substr((string) $k, 5))] = (string) $v;
            } elseif (in_array($k, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true)) {
                $headers[str_replace('_', '-', (string) $k)] = (string) $v;
            }
        }

        return new self(strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')), $headers, $_GET, $_POST, (string) file_get_contents('php://input'));
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    public function isForm(): bool
    {
        $ct = strtolower(trim(explode(';', $this->header('content-type') ?? '')[0]));

        return $ct === 'application/x-www-form-urlencoded';
    }

    /** A single-valued string parameter from $source ('query' | 'post'); arrays are not parameters. */
    public function param(string $name, string $source): ?string
    {
        $bag = $source === 'query' ? $this->query : $this->post;
        if (!array_key_exists($name, $bag)) {
            return null;
        }
        $v = $bag[$name];

        return is_string($v) ? $v : (is_scalar($v) ? (string) $v : '');
    }

    /** true when $name was sent as an array (name[]=…): RFC 6749 §3.1 forbids repeated parameters. */
    public function isArrayParam(string $name, string $source): bool
    {
        $bag = $source === 'query' ? $this->query : $this->post;

        return isset($bag[$name]) && is_array($bag[$name]);
    }
}
