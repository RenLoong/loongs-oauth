<?php

declare(strict_types=1);

namespace Loongs\OAuth\Framework;

use Closure;
use Loongs\Http\Request;
use Loongs\OAuth\Authorization\AuthorizationHandlerInterface;
use Loongs\OAuth\AuthorizationServer;
use Loongs\Routing\Router;

/**
 * Registers the authorization-server endpoints on a loongs/framework Router. Paths come from the
 * server's config (endpoint URLs relative to the issuer) and RFC 8414 metadata lives at
 * /.well-known/oauth-authorization-server{issuer path}. $server may be a Closure(Request) so one
 * route set can serve many tenants.
 */
final class OAuthRoutes
{
    /**
     * @param AuthorizationServer|Closure(Request): AuthorizationServer $server
     * @param AuthorizationHandlerInterface|Closure $handler login + consent step of the host app
     * @param AuthorizationServer|null $template server used only to derive the paths when $server is a Closure
     * @return list<string> registered "METHOD path" lines
     */
    public static function register(Router $router, AuthorizationServer|Closure $server, AuthorizationHandlerInterface|Closure $handler, ?AuthorizationServer $template = null): array
    {
        $resolve = $server instanceof AuthorizationServer ? static fn (): AuthorizationServer => $server : $server;
        $paths = $template ?? ($server instanceof AuthorizationServer ? $server : throw new \InvalidArgumentException('Pass $template when $server is a resolver.'));
        $path = static fn (string $name): string => (string) parse_url($paths->config->endpoint($name), PHP_URL_PATH);
        $out = [];
        $add = static function (string $method, string $p, Closure $action) use ($router, &$out): void {
            $router->add($method, $p, $action);
            $out[] = "{$method} {$p}";
        };

        $add('GET', $paths->metadataPath(), static fn (Request $r) => Bridge::response($resolve($r)->metadataResponse()));
        $authorize = static fn (Request $r) => Bridge::response($resolve($r)->authorize(Bridge::request($r), $handler));
        $add('GET', $path('authorization'), $authorize);
        $add('POST', $path('authorization'), $authorize);
        $add('POST', $path('token'), static fn (Request $r) => Bridge::response($resolve($r)->token(Bridge::request($r))));
        $add('POST', $path('revocation'), static fn (Request $r) => Bridge::response($resolve($r)->revoke(Bridge::request($r))));
        $add('POST', $path('introspection'), static fn (Request $r) => Bridge::response($resolve($r)->introspect(Bridge::request($r))));
        if ($paths->config->verificationKeys !== []) {
            $add('GET', $path('jwks'), static fn (Request $r) => Bridge::response($resolve($r)->jwksResponse()));
        }

        return $out;
    }
}
