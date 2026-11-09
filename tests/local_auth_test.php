<?php

declare(strict_types=1);

/**
 * Local (no-DB) JWE resource-server auth + expired/invalid reason distinction.
 * Run: D:\php\84\php.exe tests/local_auth_test.php
 */

$local = dirname(__DIR__) . '/tests/_autoload.php';
if (is_file($local)) {
    require $local;
} else {
    fwrite(STDERR, "Missing tests/_autoload.php\n");
    exit(2);
}

use Loongs\OAuth\Exception\OAuthException;
use Loongs\OAuth\Http\OAuthRequest;
use Loongs\OAuth\Jwt\EncryptionKey;
use Loongs\OAuth\Jwt\Jwe;
use Loongs\OAuth\Jwt\Jwt;
use Loongs\OAuth\Jwt\SigningKey;
use Loongs\OAuth\ResourceServer;
use Loongs\OAuth\ServerConfig;
use Loongs\OAuth\Support\Crypto;

$fail = 0;
$check = static function (string $name, bool $ok, string $detail = '') use (&$fail): void {
    if ($ok) {
        fwrite(STDOUT, "OK  {$name}" . ($detail !== '' ? " — {$detail}" : '') . "\n");
    } else {
        ++$fail;
        fwrite(STDERR, "FAIL {$name}" . ($detail !== '' ? " — {$detail}" : '') . "\n");
    }
};

$issuer = 'https://auth.example.com';
$signing = SigningKey::generate('ES256');
$enc = EncryptionKey::generateDirect();
$config = new ServerConfig(
    issuer: $issuer,
    scopes: ['profile', 'openid'],
    defaultScopes: ['profile'],
    accessTokenTtl: 900,
    accessTokenFormat: ServerConfig::FORMAT_JWE,
    signingKey: $signing,
    encryptionKey: $enc,
    jwtLeeway: 0,
);

$mint = static function (array $claims) use ($signing, $enc): string {
    return Jwe::encrypt(Jwt::encode($claims, $signing, ['typ' => 'at+jwt']), $enc, ['typ' => 'at+jwt', 'cty' => 'JWT']);
};

$now = time();
$jti = Crypto::id();
$goodClaims = [
    'iss' => $issuer,
    'exp' => $now + 600,
    'aud' => $issuer,
    'sub' => 'user-1',
    'client_id' => 'client-1',
    'iat' => $now,
    'jti' => $jti,
    'scope' => 'profile',
];
$good = $mint($goodClaims);

$rs = ResourceServer::local($config);
$check('local() builds without store', $rs->isLocal());

$info = $rs->validate($good, $now);
$check('local validate OK', $info->clientId === 'client-1' && $info->userId === 'user-1' && $info->jti === $jti && $info->hasScope('profile'));

$req = OAuthRequest::fromArrays('GET', ['Authorization' => 'Bearer ' . $good]);
$info2 = $rs->authenticate($req);
$check('local authenticate OK', $info2->jti === $jti);

$expiredTok = $mint([
    'iss' => $issuer, 'exp' => $now - 10, 'aud' => $issuer, 'sub' => 'user-1',
    'client_id' => 'client-1', 'iat' => $now - 100, 'jti' => Crypto::id(), 'scope' => 'profile',
]);
try {
    $rs->validate($expiredTok, $now);
    $check('expired throws', false);
} catch (OAuthException $e) {
    $check('expired reason', $e->error === 'invalid_token' && $e->isExpired() && $e->reason === OAuthException::REASON_EXPIRED);
    $check('expired description', str_contains($e->description, 'expired'));
    $arr = $e->toArray();
    $check('expired toArray has reason', ($arr['reason'] ?? null) === 'expired');
    $wa = $e->headers['WWW-Authenticate'] ?? '';
    $check('expired WWW-Authenticate', str_contains($wa, 'invalid_token') && str_contains($wa, 'expired'));
}

try {
    $rs->validate('not-a-jwe', $now);
    $check('opaque on local throws', false);
} catch (OAuthException $e) {
    $check('opaque on local → invalid', $e->reason === OAuthException::REASON_INVALID && !$e->isExpired());
}

try {
    $rs->validate('eyJ.not.a.real.jwe', $now);
    $check('malformed JWE throws', false);
} catch (OAuthException $e) {
    $check('malformed → invalid', $e->reason === OAuthException::REASON_INVALID);
}

$badIss = $mint([
    'iss' => 'https://evil.example', 'exp' => $now + 600, 'aud' => $issuer, 'sub' => 'user-1',
    'client_id' => 'client-1', 'iat' => $now, 'jti' => Crypto::id(), 'scope' => 'profile',
]);
try {
    $rs->validate($badIss, $now);
    $check('wrong iss throws', false);
} catch (OAuthException $e) {
    $check('wrong iss → invalid (not expired)', $e->reason === OAuthException::REASON_INVALID);
}

// Plain JWS (unencrypted) must be rejected even if signature would verify
$plain = Jwt::encode($goodClaims, $signing, ['typ' => 'at+jwt']);
try {
    $rs->validate($plain, $now);
    $check('plain JWS rejected', false);
} catch (OAuthException $e) {
    $check('plain JWS → invalid', $e->reason === OAuthException::REASON_INVALID);
}

try {
    ResourceServer::local(new ServerConfig(issuer: $issuer, accessTokenFormat: ServerConfig::FORMAT_OPAQUE));
    $check('local without keys throws', false);
} catch (InvalidArgumentException $e) {
    $check('local without keys throws', str_contains($e->getMessage(), 'verificationKeys'));
}

fwrite(STDOUT, $fail === 0 ? "\nAll local_auth tests passed.\n" : "\n{$fail} failure(s).\n");
exit($fail === 0 ? 0 : 1);
