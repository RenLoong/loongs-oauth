<?php

declare(strict_types=1);

namespace Loongs\OAuth\Framework;

use Closure;
use Loongs\Http\Request;
use Loongs\Http\Response;
use Loongs\Middleware\MiddlewareInterface;
use Loongs\OAuth\Exception\OAuthException;
use Loongs\OAuth\ResourceServer;

/**
 * Resource-server middleware for loongs/framework. Validates the bearer token (Authorization header
 * or form body; query string rejected), requires scopes, answers 400/401/403 with WWW-Authenticate,
 * and on success sets request attributes: oauth (TokenInfo), oauth_client_id, oauth_user_id, oauth_scopes.
 *
 *   // per route, with an instance (tenant-aware resolver or a fixed ResourceServer):
 *   $router->get('/api/me', $action, [BearerMiddleware::for($resolver, 'profile')]);
 *   // or by class name after BearerMiddleware::resolveUsing($resolver):
 *   final class RequireWrite extends BearerMiddleware { protected array $scopes = ['write']; }
 */
class BearerMiddleware implements MiddlewareInterface
{
    /** @var (Closure(Request): ResourceServer)|null */
    private static ?Closure $defaultResolver = null;

    /** @var list<string> */
    protected array $scopes = [];

    /** @var (Closure(Request): ResourceServer)|null */
    private ?Closure $resolver = null;

    /** @param list<string> $scopes */
    public function __construct(array $scopes = [])
    {
        if ($scopes !== []) {
            $this->scopes = $scopes;
        }
    }

    /** @param ResourceServer|Closure(Request): ResourceServer $server */
    public static function for(ResourceServer|Closure $server, string ...$scopes): static
    {
        $m = new static(array_values($scopes));
        $m->resolver = $server instanceof ResourceServer ? static fn (): ResourceServer => $server : $server;

        return $m;
    }

    /** Resolver for middleware built by the container (class-string routes). @param (Closure(Request): ResourceServer)|null $resolver */
    public static function resolveUsing(?Closure $resolver): void
    {
        self::$defaultResolver = $resolver;
    }

    public function handle(Request $request, Closure $next): Response
    {
        $resolver = $this->resolver ?? self::$defaultResolver ?? throw new \LogicException('BearerMiddleware has no ResourceServer (use BearerMiddleware::for() or resolveUsing()).');
        $server = $resolver($request);
        try {
            $info = $server->authenticate(Bridge::request($request), $this->scopes);
        } catch (OAuthException $e) {
            return Bridge::response($e->toResponse());
        }
        $request->setAttribute('oauth', $info);
        $request->setAttribute('oauth_client_id', $info->clientId);
        $request->setAttribute('oauth_user_id', $info->userId);
        $request->setAttribute('oauth_scopes', $info->scopes);

        return $next($request);
    }
}
