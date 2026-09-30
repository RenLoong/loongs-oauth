<?php

declare(strict_types=1);

namespace Loongs\OAuth\Http;

/** Framework-neutral response. Convert with Framework\Bridge::response() or send() for plain PHP. */
final readonly class OAuthResponse
{
    /** @param array<string, string> $headers */
    public function __construct(
        public int $status,
        public array $headers = [],
        public string $body = '',
    ) {
    }

    /**
     * JSON with Cache-Control: no-store (RFC 6749 §5.1 / §5.2).
     *
     * @param array<string, mixed> $data
     * @param array<string, string> $headers
     */
    public static function json(array $data, int $status = 200, array $headers = [], bool $noStore = true): self
    {
        $h = ['Content-Type' => 'application/json; charset=utf-8'];
        if ($noStore) {
            $h['Cache-Control'] = 'no-store';
            $h['Pragma'] = 'no-cache';
        }

        return new self($status, $h + $headers, (string) json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    public static function redirect(string $location, int $status = 302): self
    {
        return new self($status, ['Location' => $location, 'Cache-Control' => 'no-store']);
    }

    public static function html(string $html, int $status = 200): self
    {
        return new self($status, ['Content-Type' => 'text/html; charset=utf-8', 'Cache-Control' => 'no-store'], $html);
    }

    public function withBody(string $body): self
    {
        return new self($this->status, $this->headers, $body);
    }

    /** @return array<string, mixed>|null */
    public function data(): ?array
    {
        $d = json_decode($this->body, true);

        return is_array($d) ? $d : null;
    }

    public function header(string $name): ?string
    {
        foreach ($this->headers as $k => $v) {
            if (strcasecmp($k, $name) === 0) {
                return $v;
            }
        }

        return null;
    }

    /** Emit with the SAPI (php-fpm / built-in server). */
    public function send(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as $k => $v) {
            header("{$k}: {$v}");
        }
        echo $this->body;
    }
}
