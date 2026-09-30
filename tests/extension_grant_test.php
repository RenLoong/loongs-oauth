<?php

declare(strict_types=1);

/**
 * Extension grants (RFC 6749 §4.5): AuthorizationServer::registerGrant() + Client extension grant types.
 * Pure PHP (MemoryStorage, fixed clock) — no Swoole / DB / Redis. Run: php tests/extension_grant_test.php
 */

spl_autoload_register(static function (string $class): void {
    $prefix = 'Loongs\\OAuth\\';
    if (str_starts_with($class, $prefix)) {
        $file = dirname(__DIR__) . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});

use Loongs\OAuth\AuthorizationServer;
use Loongs\OAuth\Entity\Client;
use Loongs\OAuth\Exception\OAuthException;
use Loongs\OAuth\Grant\ExtensionGrantHandler;
use Loongs\OAuth\Grant\ExtensionGrantResult;
use Loongs\OAuth\Http\OAuthRequest;
use Loongs\OAuth\ServerConfig;
use Loongs\OAuth\Storage\MemoryStorage;
use Loongs\OAuth\Storage\Stores;

$pass = $fail = 0;
function t(string $name, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    $ok ? $pass++ : $fail++;
    printf("%s  %-66s %s\n", $ok ? 'PASS' : 'FAIL', $name, $ok ? '' : $detail);
}
function throws(callable $fn): ?string
{
    try {
        $fn();
    } catch (Throwable $e) {
        return get_class($e) . ': ' . $e->getMessage();
    }

    return null;
}

const WX = 'urn:example:params:oauth:grant-type:wechat-mini';
const FORM = ['content-type' => 'application/x-www-form-urlencoded'];

final class WechatHandler implements ExtensionGrantHandler
{
    /** @var array<string, string> code → user id */
    public array $bound = ['code-alice' => 'u1'];

    public function handle(OAuthRequest $request, Client $client, AuthorizationServer $server): ExtensionGrantResult
    {
        $code = $request->param('code', 'post');
        if ($code === null || $code === '') {
            throw OAuthException::invalidRequest('Missing code.');
        }
        if (!isset($this->bound[$code])) {
            throw OAuthException::invalidGrant('Not bound; sign in with a password first.');
        }

        return new ExtensionGrantResult($this->bound[$code], extra: ['bound' => true, 'access_token' => 'must-not-override']);
    }
}

$now = 1_900_000_000;
$mem = new MemoryStorage();
$as = new AuthorizationServer(new ServerConfig('https://as.example', ['read', 'admin', 'profile'], ['read'], accessTokenTtl: 900),
    Stores::of($mem), static function () use (&$now): int {
        return $now;
    });
$h = new WechatHandler();

// ---- registration + client validation
t('registerGrant rejects built-in / non-URI / password types', throws(fn () => $as->registerGrant('refresh_token', $h)) !== null
    && throws(fn () => $as->registerGrant('password', $h)) !== null && throws(fn () => $as->registerGrant('wechat mini', $h)) !== null);
$as->registerGrant(WX, $h);
t('grantTypes() / metadata list the extension grant', $as->grantTypes() === ['authorization_code', 'refresh_token', 'client_credentials', WX]
    && $as->metadata()['grant_types_supported'] === $as->grantTypes(), json_encode($as->metadata()['grant_types_supported']));
t('Client accepts an extension grant URI, still rejects "password"', throws(fn () => Client::public('x', 'X', ['https://x/cb'], ['read'], true, [WX])) === null
    && throws(fn () => new Client('y', 'Y', null, [], ['password'], ['read'], Client::AUTH_NONE)) !== null);
t('Client::isExtensionGrantType', Client::isExtensionGrantType(WX) && Client::isExtensionGrantType('https://example.com/grant')
    && !Client::isExtensionGrantType('authorization_code') && !Client::isExtensionGrantType('plain') && !Client::isExtensionGrantType('urn:x#frag'));
$mem->saveClient(Client::public('mp', 'Mini program', ['loongs-mp://auth'], ['read', 'profile'], true, [WX]));
$mem->saveClient(Client::public('web', 'Web', ['https://web/cb'], ['read']));
$mem->saveClient(Client::public('noref', 'No refresh', ['https://nr/cb'], ['read'], false, [WX]));

$token = static fn (array $p): array => (function () use ($as, $p): array {
    $r = $as->token(OAuthRequest::fromArrays('POST', FORM, [], $p));

    return [$r->status, $r->data() ?? []];
})();

// ---- happy path
[$st, $d] = $token(['grant_type' => WX, 'client_id' => 'mp', 'code' => 'code-alice']);
t('extension grant → 200 access + refresh token, default scope', $st === 200 && isset($d['access_token'], $d['refresh_token']) && $d['scope'] === 'read'
    && $d['expires_in'] === 900 && $d['token_type'] === 'Bearer', json_encode($d));
t('extra members merged, standard members not overridable', ($d['bound'] ?? null) === true && $d['access_token'] !== 'must-not-override');
$info = $as->resourceServer()->validate($d['access_token'], $now);
t('access token validates → user u1, client mp', $info->userId === 'u1' && $info->clientId === 'mp', json_encode([$info->userId, $info->clientId]));
[$st2, $d2] = $token(['grant_type' => WX, 'client_id' => 'mp', 'code' => 'code-alice', 'scope' => 'read profile']);
t('requested scope within client scopes honoured', $st2 === 200 && $d2['scope'] === 'read profile', json_encode($d2));

// ---- refresh rotation + reuse detection on an extension-grant family
[$sr, $r1] = $token(['grant_type' => 'refresh_token', 'client_id' => 'mp', 'refresh_token' => $d['refresh_token']]);
t('refresh token from extension grant rotates', $sr === 200 && isset($r1['refresh_token']) && $r1['refresh_token'] !== $d['refresh_token'], json_encode($r1));
[$sr2, $r2] = $token(['grant_type' => 'refresh_token', 'client_id' => 'mp', 'refresh_token' => $d['refresh_token']]);
[$sr3, $r3] = $token(['grant_type' => 'refresh_token', 'client_id' => 'mp', 'refresh_token' => $r1['refresh_token']]);
t('reuse of rotated token → invalid_grant and whole family revoked', $sr2 === 400 && $r2['error'] === 'invalid_grant' && $sr3 === 400, json_encode([$r2, $r3]));
t('other family (second login) unaffected', $as->resourceServer()->validate($d2['access_token'], $now)->userId === 'u1');

// ---- rejections
[$s, $e] = $token(['grant_type' => WX, 'client_id' => 'mp', 'code' => 'code-unknown']);
t('handler invalid_grant → 400 with its description', $s === 400 && $e['error'] === 'invalid_grant' && $e['error_description'] === 'Not bound; sign in with a password first.', json_encode($e));
[$s, $e] = $token(['grant_type' => WX, 'client_id' => 'mp']);
t('handler invalid_request (missing code) → 400', $s === 400 && $e['error'] === 'invalid_request', json_encode($e));
[$s, $e] = $token(['grant_type' => WX, 'client_id' => 'web', 'code' => 'code-alice']);
t('client without the grant type → unauthorized_client', $s === 400 && $e['error'] === 'unauthorized_client', json_encode($e));
[$s, $e] = $token(['grant_type' => 'urn:example:not-registered', 'client_id' => 'mp', 'code' => 'x']);
t('unregistered extension grant → unsupported_grant_type', $s === 400 && $e['error'] === 'unsupported_grant_type', json_encode($e));
[$s, $e] = $token(['grant_type' => WX, 'client_id' => 'nobody', 'code' => 'code-alice']);
t('unknown client → 401 invalid_client', $s === 401 && $e['error'] === 'invalid_client', json_encode($e));
[$s, $e] = $token(['grant_type' => WX, 'client_id' => 'mp', 'code' => 'code-alice', 'scope' => 'admin']);
t('scope outside the client → invalid_scope', $s === 400 && $e['error'] === 'invalid_scope', json_encode($e));
[$s, $e] = $token(['grant_type' => WX, 'client_id' => 'noref', 'code' => 'code-alice']);
t('client without refresh_token grant → no refresh token', $s === 200 && !isset($e['refresh_token']), json_encode($e));

// ---- closure handler, refreshToken=false, explicit scopes, bad return type
$as->registerGrant('urn:example:closure', static fn (OAuthRequest $r, Client $c) => new ExtensionGrantResult('u9', ['profile'], false));
$mem->saveClient(Client::public('cl', 'Closure', ['https://cl/cb'], ['read', 'profile'], true, ['urn:example:closure', 'urn:example:bad']));
[$s, $e] = $token(['grant_type' => 'urn:example:closure', 'client_id' => 'cl']);
t('closure handler; result scopes + refreshToken=false respected', $s === 200 && $e['scope'] === 'profile' && !isset($e['refresh_token'])
    && $as->resourceServer()->validate($e['access_token'], $now)->userId === 'u9', json_encode($e));
$as->registerGrant('urn:example:bad', static fn () => ['user' => 'x']);
$bad = throws(fn () => $token(['grant_type' => 'urn:example:bad', 'client_id' => 'cl']));
[$s, $e] = $bad === null ? $token(['grant_type' => 'urn:example:bad', 'client_id' => 'cl']) : [0, []];
t('handler returning a non-result → 500 server_error (TypeError-safe)', $s === 500 && $e['error'] === 'server_error', (string) $bad . json_encode($e));
t('ExtensionGrantResult rejects an empty user id', throws(fn () => new ExtensionGrantResult('')) !== null);
[$s, $e] = $token(['grant_type' => 'password', 'client_id' => 'mp', 'username' => 'a', 'password' => 'b']);
t('password grant still unsupported', $s === 400 && $e['error'] === 'unsupported_grant_type', json_encode($e));

printf("\nEXTENSION_GRANT_TEST %s  passed=%d failed=%d\n", $fail === 0 ? 'ALL PASS' : 'FAILED', $pass, $fail);
exit($fail === 0 ? 0 : 1);
