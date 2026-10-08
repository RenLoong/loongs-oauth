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
use Loongs\Orm\Query\Expression;

/**
 * loongs/orm storage (MySQL / MariaDB). Connection resolved per call like every loongs/orm call:
 *   new OrmStorage()                 → the default connection: inside a loongs/saas Tenancy::run() scope the
 *                                      current coroutine's tenant, else the configured default
 *   new OrmStorage($tenantSpec)      → that tenant (name, config array, DSN, ConnectionConfig), every call
 *   $storage->on($otherTenant)       → a copy bound to another tenant
 *
 * Table names = <connection prefix> + "oauth_" + table ("app_" + "oauth_clients"). The prefix,
 * engine, charset and collation come from the connection's config through loongs/orm
 * (Orm::config($spec)->tableOptions(): config arrays, named connections, mysql://…?prefix=, and the
 * current loongs/saas tenant scope), resolved on every call; constructor values override them.
 * install() / OrmStorage::installOn() generate the DDL from those values (CREATE TABLE IF NOT
 * EXISTS: idempotent), and every query uses the same names (the query builder applies the
 * connection prefix). No PDO is held: every statement leases a pooled connection. Check-and-set
 * operations are single atomic UPDATEs.
 */
final readonly class OrmStorage implements StorageInterface
{
    public const string TABLES = 'oauth_';

    /** @var list<string> */
    public const array TABLE_NAMES = ['clients', 'auth_codes', 'access_tokens', 'refresh_tokens', 'token_families', 'consents'];

    /**
     * @param string|array<string, mixed>|ConnectionConfig|null $connection
     * @param string|null $prefix  table prefix override (null = the connection's own prefix, auto-detected)
     * @param string $tables       base prefix of the OAuth tables (after the connection prefix)
     * @param string|null $engine  null = the connection's engine, else InnoDB
     * @param string|null $charset null = the connection's charset (utf8mb4 by default)
     * @param string|null $collation null = the connection's collation, else <charset>_bin
     */
    public function __construct(
        private string|array|ConnectionConfig|null $connection = null,
        private ?string $prefix = null,
        private string $tables = self::TABLES,
        private ?string $engine = null,
        private ?string $charset = null,
        private ?string $collation = null,
    ) {
        foreach ([$prefix, $tables] as $v) {
            if ($v !== null && preg_match('/^[A-Za-z0-9_]{0,48}$/', $v) !== 1) {
                throw new \InvalidArgumentException('Table prefixes may only contain [A-Za-z0-9_].');
            }
        }
    }

    /** @param string|array<string, mixed>|ConnectionConfig|null $connection */
    public function on(string|array|ConnectionConfig|null $connection): self
    {
        return new self($connection, $this->prefix, $this->tables, $this->engine, $this->charset, $this->collation);
    }

    /**
     * Create the OAuth tables in $connection (connection name, tenant config array, DSN / URL,
     * ConnectionConfig) with DDL generated from that connection's config. Idempotent.
     *
     * @param string|array<string, mixed>|ConnectionConfig|null $connection
     * @return array<string, bool> table name => true if created now, false if it already existed
     */
    public static function installOn(string|array|ConnectionConfig|null $connection, ?string $prefix = null, string $tables = self::TABLES,
        ?string $engine = null, ?string $charset = null, ?string $collation = null): array
    {
        return (new self($connection, $prefix, $tables, $engine, $charset, $collation))->install();
    }

    /**
     * Create the tables (idempotent) on this storage's connection / tenant.
     *
     * @return array<string, bool> table name => true if created now, false if it already existed
     */
    public function install(): array
    {
        $o = $this->options();
        $c = $this->db();
        $out = [];
        foreach ($this->schema($o) as $table => $ddl) {
            $exists = $c->selectOne('SELECT 1 AS x FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?', [$table]) !== null;
            if (!$exists) {
                $c->unprepared($ddl);
            }
            $out[$table] = !$exists;
        }

        return $out;
    }

    /**
     * The CREATE TABLE IF NOT EXISTS statements for this storage's connection (dry run).
     *
     * @param array{prefix: string, engine: string, charset: string, collation: string}|null $o
     * @return array<string, string> table name => DDL
     */
    public function schema(?array $o = null): array
    {
        $o ??= $this->options();
        $bin = $o['charset'] . '_bin';
        $id = static fn (int $len): string => "VARCHAR({$len}) COLLATE {$bin}";   // identifiers: case-sensitive, whatever the table collation
        $hash = 'CHAR(64) CHARACTER SET ascii COLLATE ascii_bin';
        $fam = 'CHAR(32) CHARACTER SET ascii COLLATE ascii_bin';
        $t = fn (string $name): string => $o['prefix'] . $this->tables . $name;
        $defs = [
            'clients' => ["client_id {$id(100)} NOT NULL PRIMARY KEY", 'name VARCHAR(191) NOT NULL', 'secret_hash VARCHAR(255) NULL',
                'redirect_uris TEXT NOT NULL', 'grant_types VARCHAR(255) NOT NULL', 'scopes TEXT NOT NULL',
                'token_endpoint_auth_method VARCHAR(32) NOT NULL', 'can_introspect TINYINT(1) NOT NULL DEFAULT 0', 'created_at INT UNSIGNED NOT NULL DEFAULT 0'],
            'auth_codes' => ["code_hash {$hash} NOT NULL PRIMARY KEY", "client_id {$id(100)} NOT NULL", "user_id {$id(191)} NOT NULL", 'redirect_uri TEXT NOT NULL',
                'redirect_uri_provided TINYINT(1) NOT NULL', 'scopes TEXT NOT NULL', 'code_challenge VARCHAR(128) NOT NULL', 'code_challenge_method VARCHAR(10) NOT NULL',
                "family_id {$fam} NOT NULL", 'expires_at INT UNSIGNED NOT NULL', 'used_at INT UNSIGNED NULL', 'created_at INT UNSIGNED NOT NULL',
                "KEY `{$t('auth_codes')}_expires` (expires_at)"],
            'access_tokens' => ["token_hash {$hash} NOT NULL PRIMARY KEY", "jti {$fam} NOT NULL", "format VARCHAR(8) NOT NULL DEFAULT 'opaque'", "client_id {$id(100)} NOT NULL",
                "user_id {$id(191)} NULL", 'scopes TEXT NOT NULL', "family_id {$fam} NOT NULL", 'issued_at INT UNSIGNED NOT NULL', 'expires_at INT UNSIGNED NOT NULL',
                'revoked_at INT UNSIGNED NULL', "KEY `{$t('access_tokens')}_family` (family_id)", "KEY `{$t('access_tokens')}_expires` (expires_at)"],
            'refresh_tokens' => ["token_hash {$hash} NOT NULL PRIMARY KEY", "client_id {$id(100)} NOT NULL", "user_id {$id(191)} NULL", 'scopes TEXT NOT NULL',
                "family_id {$fam} NOT NULL", 'issued_at INT UNSIGNED NOT NULL', 'expires_at INT UNSIGNED NOT NULL', 'rotated_at INT UNSIGNED NULL', 'revoked_at INT UNSIGNED NULL',
                "KEY `{$t('refresh_tokens')}_family` (family_id)", "KEY `{$t('refresh_tokens')}_expires` (expires_at)"],
            'token_families' => ["family_id {$fam} NOT NULL PRIMARY KEY", 'revoked_at INT UNSIGNED NOT NULL', 'reason VARCHAR(32) NOT NULL'],
            'consents' => ["user_id {$id(191)} NOT NULL", "client_id {$id(100)} NOT NULL", 'scopes TEXT NOT NULL', 'granted_at INT UNSIGNED NOT NULL', 'PRIMARY KEY (user_id, client_id)'],
        ];
        $out = [];
        foreach ($defs as $name => $cols) {
            $out[$t($name)] = 'CREATE TABLE IF NOT EXISTS `' . $t($name) . "` (\n  " . implode(",\n  ", $cols)
                . "\n) ENGINE={$o['engine']} DEFAULT CHARSET={$o['charset']} COLLATE={$o['collation']}";
        }

        return $out;
    }

    /** Resolved table name, e.g. table('clients') → "app_oauth_clients". */
    public function table(string $name): string
    {
        return $this->options()['prefix'] . $this->tables . $name;
    }

    /**
     * Table options for this storage: explicit values, else the connection's config (loongs/orm
     * ConnectionConfig::tableOptions(), resolved per call — also inside Tenancy::run()), else defaults.
     *
     * @return array{prefix: string, engine: string, charset: string, collation: string}
     */
    public function options(): array
    {
        $cfg = Orm::config($this->connection);
        $charset = $this->charset ?? $cfg->charset();
        $o = ['prefix' => $this->prefix ?? $cfg->prefix(), 'engine' => $this->engine ?? $cfg->engine() ?? 'InnoDB',
            'charset' => $charset, 'collation' => $this->collation ?? $cfg->collation() ?? $charset . '_bin'];
        foreach ($o as $k => $v) {
            if (preg_match($k === 'prefix' ? '/^[A-Za-z0-9_]{0,64}$/' : '/^[A-Za-z0-9_]{1,64}$/', $v) !== 1) {
                throw new \InvalidArgumentException("Invalid table {$k} [{$v}].");
            }
        }

        return $o;
    }

    private function db(): Connection
    {
        return Orm::connection($this->connection);
    }

    private function t(string $table): Builder
    {
        $c = $this->db();
        $logical = $this->tables . $table;

        // the query builder prefixes with the connection's own prefix; an explicit, different override is passed verbatim
        return $this->prefix === null || $this->prefix === $c->prefix()
            ? $c->table($logical)
            : $c->table(new Expression($c->getGrammar()->wrapValue($this->prefix . $logical)));
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
            'INSERT INTO `' . $this->table('consents') . '` (user_id, client_id, scopes, granted_at) VALUES (?, ?, ?, ?) '
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
