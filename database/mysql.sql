-- loongs/oauth — MySQL 8 / MariaDB 10.5+ schema. One set per tenant database (OrmStorage::install()
-- runs this file; the "oauth_" prefix is replaced when a different table prefix is configured).
-- Times are UNIX seconds. Codes and tokens are stored only as HMAC-SHA-256 hashes; client secrets as
-- password_hash() output.

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id VARCHAR(100) NOT NULL PRIMARY KEY,
  name VARCHAR(191) NOT NULL,
  secret_hash VARCHAR(255) NULL,
  redirect_uris TEXT NOT NULL,
  grant_types VARCHAR(255) NOT NULL,
  scopes TEXT NOT NULL,
  token_endpoint_auth_method VARCHAR(32) NOT NULL,
  can_introspect TINYINT(1) NOT NULL DEFAULT 0,
  created_at INT UNSIGNED NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS oauth_auth_codes (
  code_hash CHAR(64) NOT NULL PRIMARY KEY,
  client_id VARCHAR(100) NOT NULL,
  user_id VARCHAR(191) NOT NULL,
  redirect_uri TEXT NOT NULL,
  redirect_uri_provided TINYINT(1) NOT NULL,
  scopes TEXT NOT NULL,
  code_challenge VARCHAR(128) NOT NULL,
  code_challenge_method VARCHAR(10) NOT NULL,
  family_id CHAR(32) NOT NULL,
  expires_at INT UNSIGNED NOT NULL,
  used_at INT UNSIGNED NULL,
  created_at INT UNSIGNED NOT NULL,
  KEY oauth_auth_codes_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS oauth_access_tokens (
  token_hash CHAR(64) NOT NULL PRIMARY KEY,
  jti CHAR(32) NOT NULL,
  format VARCHAR(8) NOT NULL DEFAULT 'opaque',
  client_id VARCHAR(100) NOT NULL,
  user_id VARCHAR(191) NULL,
  scopes TEXT NOT NULL,
  family_id CHAR(32) NOT NULL,
  issued_at INT UNSIGNED NOT NULL,
  expires_at INT UNSIGNED NOT NULL,
  revoked_at INT UNSIGNED NULL,
  KEY oauth_access_tokens_family (family_id),
  KEY oauth_access_tokens_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  token_hash CHAR(64) NOT NULL PRIMARY KEY,
  client_id VARCHAR(100) NOT NULL,
  user_id VARCHAR(191) NULL,
  scopes TEXT NOT NULL,
  family_id CHAR(32) NOT NULL,
  issued_at INT UNSIGNED NOT NULL,
  expires_at INT UNSIGNED NOT NULL,
  rotated_at INT UNSIGNED NULL,
  revoked_at INT UNSIGNED NULL,
  KEY oauth_refresh_tokens_family (family_id),
  KEY oauth_refresh_tokens_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS oauth_token_families (
  family_id CHAR(32) NOT NULL PRIMARY KEY,
  revoked_at INT UNSIGNED NOT NULL,
  reason VARCHAR(32) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS oauth_consents (
  user_id VARCHAR(191) NOT NULL,
  client_id VARCHAR(100) NOT NULL,
  scopes TEXT NOT NULL,
  granted_at INT UNSIGNED NOT NULL,
  PRIMARY KEY (user_id, client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
