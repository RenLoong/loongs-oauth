<?php

declare(strict_types=1);

namespace Loongs\OAuth\Storage;

use Loongs\OAuth\Entity\AccessToken;
use Loongs\OAuth\Entity\AuthorizationCode;
use Loongs\OAuth\Entity\Client;
use Loongs\OAuth\Entity\Consent;
use Loongs\OAuth\Entity\RefreshToken;
use Loongs\Orm\Connection\Connection;
use Loongs\Orm\Connection\ConnectionConfig;
use Loongs\Orm\Orm;
use Loongs\Orm\Query\Builder;

/**
 * loongs/orm storage (MySQL). Tenant-aware like every loongs/orm call:
 *   new OrmStorage()                 → the current coroutine's Orm::tenant() scope, else the default connection
 *   new OrmStorage($tenantSpec)      → that tenant (name, config array, DSN, ConnectionConfig), every call
 *   $storage->on($otherTenant)       → a copy bound to another tenant
 * Each tenant database has its own oauth_* tables (OrmStorage::install()). No PDO is held: every
 * statement leases a pooled connection. Check-and-set operations are single atomic UPDATEs.
 */
final readonly class OrmStorage implements StorageInterface
{
    /** @param string|array<string, mixed>|ConnectionConfig|null $connection */
    public function __construct(
        private string|array|ConnectionConfig|null $connection = null,
        private string $prefix = 'oauth_',
    ) {
    }

    /** @param string|array<string, mixed>|ConnectionConfig|null $connection */
    public function on(string|array|ConnectionConfig|null $connection): self
    {
        return new self($connection, $this->prefix);
    }

    public static function schemaPath(): string
    {
        return dirname(__DIR__, 2) . '/database/mysql.sql';
    }

    /** Create the tables (idempotent) on this storage's connection / tenant. */
    public function install(): void
    {
        $sql = (string) file_get_contents(self::schemaPath());
        $sql = (string) preg_replace('/^--.*$/m', '', $sql);
        if ($this->prefix !== 'oauth_') {
            $sql = (string) preg_replace('/\boauth_/', $this->prefix, $sql);
        }
        $c = $this->db();
        foreach (array_filter(array_map('trim', explode(';', $sql))) as $stmt) {
            $c->unprepared($stmt);
        }
    }

    private function db(): Connection
    {
        return Orm::connection($this->connection);
    }

    private function t(string $table): Builder
    {
        return $this->db()->table($this->prefix . $table);
    }

    /** @return list<string> */
    private static function list(?string $s): array
    {
        return $s === null || $s === '' ? [] : explode(' ', $s);
    }

    private static function nint(mixed $v): ?int
    {
        return $v === null ? null : (int) $v;
    }

    // clients -------------------------------------------------------------

    public function findClient(string $clientId): ?Client
    {
        $r = $this->t('clients')->where('client_id', $clientId)->first();
        if ($r === null) {
            return null;
        }

        return new Client((string) $r['client_id'], (string) $r['name'], $r['secret_hash'] === null ? null : (string) $r['secret_hash'],
            (array) json_decode((string) $r['redirect_uris'], true), self::list($r['grant_types']), self::list($r['scopes']),
            (string) $r['token_endpoint_auth_method'], (bool) $r['can_introspect'], (int) $r['created_at']);
    }

    public function saveClient(Client $client): void
    {
        $row = ['name' => $client->name, 'secret_hash' => $client->secretHash, 'redirect_uris' => json_encode($client->redirectUris, JSON_UNESCAPED_SLASHES),
            'grant_types' => implode(' ', $client->grantTypes), 'scopes' => implode(' ', $client->scopes),
            'token_endpoint_auth_method' => $client->tokenEndpointAuthMethod, 'can_introspect' => $client->canIntrospect ? 1 : 0, 'created_at' => $client->createdAt];
        if ($this->t('clients')->where('client_id', $client->id)->update($row) === 0 && !$this->t('clients')->where('client_id', $client->id)->exists()) {
            $this->t('clients')->insert(['client_id' => $client->id] + $row);
        }
    }

    public function deleteClient(string $clientId): void
    {
        $this->t('clients')->where('client_id', $clientId)->delete();
    }

    // authorization codes ------------------------------------------------

    public function saveAuthCode(AuthorizationCode $code): void
    {
        $this->t('auth_codes')->insert([
            'code_hash' => $code->codeHash, 'client_id' => $code->clientId, 'user_id' => $code->userId, 'redirect_uri' => $code->redirectUri,
            'redirect_uri_provided' => $code->redirectUriProvided ? 1 : 0, 'scopes' => implode(' ', $code->scopes),
            'code_challenge' => $code->codeChallenge, 'code_challenge_method' => $code->codeChallengeMethod, 'family_id' => $code->familyId,
            'expires_at' => $code->expiresAt, 'used_at' => $code->usedAt, 'created_at' => $code->createdAt,
        ]);
    }

    public function findAuthCode(string $codeHash): ?AuthorizationCode
    {
        $r = $this->t('auth_codes')->where('code_hash', $codeHash)->first();

        return $r === null ? null : new AuthorizationCode((string) $r['code_hash'], (string) $r['client_id'], (string) $r['user_id'],
            (string) $r['redirect_uri'], (bool) $r['redirect_uri_provided'], self::list($r['scopes']), (string) $r['code_challenge'],
            (string) $r['code_challenge_method'], (string) $r['family_id'], (int) $r['expires_at'], self::nint($r['used_at']), (int) $r['created_at']);
    }

    public function consumeAuthCode(string $codeHash, int $now): bool
    {
        return $this->t('auth_codes')->where('code_hash', $codeHash)->whereNull('used_at')->update(['used_at' => $now]) === 1;
    }

    // access tokens ------------------------------------------------------

    public function saveAccessToken(AccessToken $token): void
    {
        $this->t('access_tokens')->insert([
            'token_hash' => $token->tokenHash, 'jti' => $token->jti, 'format' => $token->format, 'client_id' => $token->clientId, 'user_id' => $token->userId,
            'scopes' => implode(' ', $token->scopes), 'family_id' => $token->familyId, 'issued_at' => $token->issuedAt,
            'expires_at' => $token->expiresAt, 'revoked_at' => $token->revokedAt,
        ]);
    }

    public function findAccessToken(string $tokenHash): ?AccessToken
    {
        $r = $this->t('access_tokens')->where('token_hash', $tokenHash)->first();

        return $r === null ? null : new AccessToken((string) $r['token_hash'], (string) $r['jti'], (string) $r['client_id'],
            $r['user_id'] === null ? null : (string) $r['user_id'], self::list($r['scopes']), (string) $r['family_id'],
            (int) $r['issued_at'], (int) $r['expires_at'], self::nint($r['revoked_at']), (string) $r['format']);
    }

    public function revokeAccessToken(string $tokenHash, int $now): void
    {
        $this->t('access_tokens')->where('token_hash', $tokenHash)->whereNull('revoked_at')->update(['revoked_at' => $now]);
    }

    // refresh tokens -----------------------------------------------------

    public function saveRefreshToken(RefreshToken $token): void
    {
        $this->t('refresh_tokens')->insert([
            'token_hash' => $token->tokenHash, 'client_id' => $token->clientId, 'user_id' => $token->userId, 'scopes' => implode(' ', $token->scopes),
            'family_id' => $token->familyId, 'issued_at' => $token->issuedAt, 'expires_at' => $token->expiresAt,
            'rotated_at' => $token->rotatedAt, 'revoked_at' => $token->revokedAt,
        ]);
    }

    public function findRefreshToken(string $tokenHash): ?RefreshToken
    {
        $r = $this->t('refresh_tokens')->where('token_hash', $tokenHash)->first();

        return $r === null ? null : new RefreshToken((string) $r['token_hash'], (string) $r['client_id'], $r['user_id'] === null ? null : (string) $r['user_id'],
            self::list($r['scopes']), (string) $r['family_id'], (int) $r['issued_at'], (int) $r['expires_at'], self::nint($r['rotated_at']), self::nint($r['revoked_at']));
    }

    public function rotateRefreshToken(string $tokenHash, int $now): bool
    {
        return $this->t('refresh_tokens')->where('token_hash', $tokenHash)->whereNull('rotated_at')->whereNull('revoked_at')->update(['rotated_at' => $now]) === 1;
    }

    public function revokeRefreshToken(string $tokenHash, int $now): void
    {
        $this->t('refresh_tokens')->where('token_hash', $tokenHash)->whereNull('revoked_at')->update(['revoked_at' => $now]);
    }

    // families -----------------------------------------------------------

    public function revokeFamily(string $familyId, int $now, string $reason): void
    {
        $this->t('token_families')->insertOrIgnore(['family_id' => $familyId, 'revoked_at' => $now, 'reason' => substr($reason, 0, 32)]);
        $this->t('access_tokens')->where('family_id', $familyId)->whereNull('revoked_at')->update(['revoked_at' => $now]);
        $this->t('refresh_tokens')->where('family_id', $familyId)->whereNull('revoked_at')->update(['revoked_at' => $now]);
    }

    public function isFamilyRevoked(string $familyId): bool
    {
        return $this->t('token_families')->where('family_id', $familyId)->exists();
    }

    // consents -----------------------------------------------------------

    public function findConsent(string $userId, string $clientId): ?Consent
    {
        $r = $this->t('consents')->where('user_id', $userId)->where('client_id', $clientId)->first();

        return $r === null ? null : new Consent((string) $r['user_id'], (string) $r['client_id'], self::list($r['scopes']), (int) $r['granted_at']);
    }

    public function saveConsent(Consent $consent): void
    {
        $this->db()->statement(
            'INSERT INTO `' . $this->prefix . 'consents` (user_id, client_id, scopes, granted_at) VALUES (?, ?, ?, ?) '
            . 'ON DUPLICATE KEY UPDATE scopes = VALUES(scopes), granted_at = VALUES(granted_at)',
            [$consent->userId, $consent->clientId, implode(' ', $consent->scopes), $consent->grantedAt],
        );
    }

    public function revokeConsent(string $userId, string $clientId): void
    {
        $this->t('consents')->where('user_id', $userId)->where('client_id', $clientId)->delete();
    }

    public function purgeExpired(int $now): int
    {
        return $this->t('auth_codes')->where('expires_at', '<', $now)->delete()
            + $this->t('access_tokens')->where('expires_at', '<', $now)->delete()
            + $this->t('refresh_tokens')->where('expires_at', '<', $now)->delete();
    }
}
