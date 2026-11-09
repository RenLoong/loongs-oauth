<?php

declare(strict_types=1);

/**
 * Dependency-free checks for Keys types (jwt | sk | token | refresh_token).
 * Run: D:\php\84\php.exe tests/key_types_test.php
 */

$local = dirname(__DIR__) . '/tests/_autoload.php';
if (is_file($local)) {
    require $local;
} else {
    $roots = [
        dirname(__DIR__) . '/vendor/autoload.php',
        dirname(__DIR__, 3) . '/server/vendor/autoload.php',
        dirname(__DIR__, 2) . '/server/vendor/autoload.php',
    ];
    $autoload = null;
    foreach ($roots as $cand) {
        if (is_file($cand)) {
            $autoload = $cand;
            break;
        }
    }
    if ($autoload === null) {
        fwrite(STDERR, "No Composer autoload found.\n");
        exit(2);
    }
    require $autoload;
}

use Loongs\OAuth\Entity\Client;
use Loongs\OAuth\Jwt\SigningKey;
use Loongs\OAuth\Support\Crypto;
use Loongs\OAuth\Support\Keys;

$fail = 0;
$check = static function (string $name, bool $ok, string $detail = '') use (&$fail): void {
    if ($ok) {
        fwrite(STDOUT, "OK  {$name}" . ($detail !== '' ? " — {$detail}" : '') . "\n");
    } else {
        ++$fail;
        fwrite(STDERR, "FAIL {$name}" . ($detail !== '' ? " — {$detail}" : '') . "\n");
    }
};

$check('Keys::TYPES lists jwt/sk/token/refresh_token', Keys::TYPES === ['jwt', 'sk', 'token', 'refresh_token']);

$es = Keys::jwt('ES256');
$check('jwt ES256 → SigningKey', $es instanceof SigningKey && $es->alg === 'ES256' && $es->kid !== '');
$rs = Keys::generate(Keys::JWT, 'RS256');
$check('generate(jwt, RS256) → SigningKey', $rs instanceof SigningKey && $rs->alg === 'RS256');
$pem = $es->toPem();
$check('jwt PEM round-trip', str_contains($pem, 'BEGIN') && SigningKey::fromPem($pem, 'ES256')->kid === $es->kid);

$sk = Keys::sk();
$check('sk has prefix + entropy', Keys::isSk($sk) && str_starts_with($sk, 'sk_') && strlen($sk) === 3 + 43);
$hash = Crypto::hashSecret($sk);
$check('sk hashed with hashSecret / verifySecret', Crypto::verifySecret($sk, $hash) && !Crypto::verifySecret($sk . 'x', $hash));
$check('generate(sk) same shape', Keys::isSk((string) Keys::generate(Keys::SK)));

$tok = Keys::token();
$rt = Keys::refreshToken();
$check('token 256-bit base64url', strlen($tok) === 43 && preg_match('/^[A-Za-z0-9_-]+$/', $tok) === 1);
$check('refresh_token 384-bit base64url (longer)', strlen($rt) === 64 && preg_match('/^[A-Za-z0-9_-]+$/', $rt) === 1 && strlen($rt) > strlen($tok));
$check('token / refresh_token unique', $tok !== Keys::token() && $rt !== Keys::refreshToken());
$th = Crypto::hashToken($tok, 'pepper');
$rh = Crypto::hashToken($rt, 'pepper');
$check('token/refresh hashed with hashToken', strlen($th) === 64 && strlen($rh) === 64 && $th !== $rh);

[$c, $secret] = Client::confidential('c-sk', 'SK client', [], ['client_credentials'], ['read']);
$check('Client::confidential secret is sk_*', Keys::isSk($secret) && Crypto::verifySecret($secret, $c->secretHash));

$threw = false;
try {
    Keys::generate('hmac');
} catch (InvalidArgumentException) {
    $threw = true;
}
$check('unknown type rejected', $threw);

fwrite(STDOUT, $fail === 0 ? "\nAll key-type checks passed.\n" : "\n{$fail} check(s) failed.\n");
exit($fail === 0 ? 0 : 1);