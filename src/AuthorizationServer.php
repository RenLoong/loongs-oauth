<?php

declare(strict_types=1);

namespace Loongs\OAuth;

use Closure;
use Loongs\Helper\Str;
use Loongs\OAuth\Authorization\AuthorizationDecision;
use Loongs\OAuth\Authorization\AuthorizationHandlerInterface;
use Loongs\OAuth\Authorization\AuthorizationRequest;
use Loongs\OAuth\Authorization\CallableAuthorizationHandler;
use Loongs\OAuth\Entity\AccessToken;
use Loongs\OAuth\Entity\AuthorizationCode;
use Loongs\OAuth\Entity\Client;
use Loongs\OAuth\Entity\Consent;
use Loongs\OAuth\Entity\RefreshToken;
use Loongs\OAuth\Exception\OAuthException;
use Loongs\OAuth\Exception\RedirectableException;
use Loongs\OAuth\Http\OAuthRequest;
use Loongs\OAuth\Http\OAuthResponse;
use Loongs\OAuth\Jwt\JwkSet;
use Loongs\OAuth\Jwt\Jwt;
use Loongs\OAuth\Storage\Stores;
use Loongs\OAuth\Support\Crypto;
use Loongs\OAuth\Support\Scope;

/**
 * OAuth 2.1 authorization server (draft-ietf-oauth-v2-1): authorization endpoint (code + PKCE),
 * token endpoint (authorization_code, refresh_token, client_credentials), RFC 7009 revocation,
 * RFC 7662 introspection, RFC 8414 metadata, JWKS. Framework-neutral: OAuthRequest in, OAuthResponse
 * out. No implicit grant, no password grant.
 */
final class AuthorizationServer
{
    public const array GRANTS = ['authorization_code', 'refresh_token', 'client_credentials'];

    private ?ResourceServer $resourceServer = null;

    /** @var Closure(): int */
    private Closure $clock;

    public function __construct(
        public readonly ServerConfig $config,
        public readonly Stores $stores,
        ?Closure $clock = null,
    ) {
        $this->clock = $clock ?? static fn (): int => time();
    }

    public function now(): int
    {
        return ($this->clock)();
    }

    public function resourceServer(): ResourceServer
    {
        return $this->resourceServer ??= ResourceServer::fromServer($this);
    }

    // ------------------------------------------------------------------ authorization endpoint

    /**
     * Full authorization endpoint (GET or POST): validate, ask the host handler (login + consent),
     * then redirect back with code + state + iss, or with an error.
     *
     * @param AuthorizationHandlerInterface|Closure(AuthorizationRequest, OAuthRequest, AuthorizationServer): AuthorizationDecision $handler
     */
    public function authorize(OAuthRequest $request, AuthorizationHandlerInterface|Closure $handler): OAuthResponse
    {
        $handler = $handler instanceof Closure ? new CallableAuthorizationHandler($handler) : $handler;
        try {
            $ar = $this->validateAuthorizationRequest($request);
        } catch (RedirectableException $e) {
            return $this->errorRedirect($e, $request->method);
        } catch (OAuthException $e) {
            // client_id / redirect_uri not trusted: never redirect (RFC 6749 §4.1.2.1)
            return $e->toResponse();
        }

        $d = $handler->handle($ar, $request, $this);

        return match ($d->kind) {
            'respond' => $d->response ?? OAuthResponse::json(['error' => 'server_error'], 500),
            'deny' => $this->errorRedirect(new RedirectableException(OAuthException::accessDenied('The resource owner denied the request.'), $ar->redirectUri, $ar->state), $request->method),
            default => $this->approve($ar, (string) $d->userId, $d->scopes, $d->remember, $request->method),
        };
    }

    /**
     * Validate an authorization request. Errors before the client and redirect URI are trusted are
     * plain OAuthExceptions (show them, do not redirect); later ones are RedirectableExceptions.
     */
    public function validateAuthorizationRequest(OAuthRequest $request): AuthorizationRequest
    {
        $src = $request->method === 'POST' ? 'post' : 'query';
        foreach (['client_id', 'redirect_uri', 'response_type', 'scope', 'state', 'code_challenge', 'code_challenge_method'] as $p) {
            if ($request->isArrayParam($p, $src)) {
                throw OAuthException::invalidRequest("Parameter [{$p}] must not be repeated.");
            }
        }
        $clientId = $request->param('client_id', $src);
        if ($clientId === null || $clientId === '') {
            throw OAuthException::invalidRequest('Missing client_id.');
        }
        $client = $this->stores->clients->findClient($clientId);
        if ($client === null) {
            throw new OAuthException('invalid_client', 'Unknown client.', 400);
        }
        $redirect = $request->param('redirect_uri', $src);
        $provided = $redirect !== null;
        if ($redirect === null) {
            if (count($client->redirectUris) !== 1) {
                throw OAuthException::invalidRequest('redirect_uri is required for this client.');
            }
            $redirect = $client->redirectUris[0];
        } elseif (!$this->redirectUriMatches($redirect, $client->redirectUris)) {
            throw OAuthException::invalidRequest('redirect_uri does not match a registered redirect URI.');
        }
        $state = $request->param('state', $src);
        $fail = static fn (OAuthException $e): RedirectableException => new RedirectableException($e, $redirect, $state);

        $responseType = $request->param('response_type', $src);
        if ($responseType === null || $responseType === '') {
            throw $fail(OAuthException::invalidRequest('Missing response_type.'));
        }
        if ($responseType !== 'code') {
            throw $fail(OAuthException::unsupportedResponseType('Only response_type=code is supported (no implicit grant).'));
        }
        if (!$client->allowsGrant('authorization_code')) {
            throw $fail(OAuthException::unauthorizedClient('This client may not use the authorization code grant.'));
        }
        try {
            $scopes = $this->resolveScopes(Scope::parse($request->param('scope', $src)), $client);
        } catch (OAuthException $e) {
            throw $fail($e);
        }

        $challenge = $request->param('code_challenge', $src);
        $method = $request->param('code_challenge_method', $src) ?? Pkce::PLAIN; // RFC 7636 default
        if ($challenge === null || $challenge === '') {
            if ($this->config->requirePkce || !$client->isConfidential()) {
                throw $fail(OAuthException::invalidRequest('code_challenge is required (PKCE).'));
            }
            $challenge = '';
            $method = '';
        } else {
            if ($method !== Pkce::S256 && !($method === Pkce::PLAIN && $this->config->allowPlainPkce)) {
                throw $fail(OAuthException::invalidRequest('Unsupported code_challenge_method; use S256.'));
            }
            if (!Pkce::isValidChallenge($challenge, $method)) {
                throw $fail(OAuthException::invalidRequest('Malformed code_challenge.'));
            }
        }

        return new AuthorizationRequest($client, $redirect, $provided, $scopes, $state, $challenge, $method);
    }

    /** Does the host already have a remembered consent covering this request? */
    public function hasConsent(string $userId, AuthorizationRequest $ar): bool
    {
        return $this->stores->consents->findConsent($userId, $ar->client->id)?->covers($ar->scopes) ?? false;
    }

    /**
     * Issue the authorization code and build the success redirect (code, state, iss).
     *
     * @param list<string>|null $scopes narrowed scopes (must be a subset of the requested ones)
     */
    public function approve(AuthorizationRequest $ar, string $userId, ?array $scopes = null, bool $remember = false, string $method = 'GET'): OAuthResponse
    {
        $granted = $scopes === null ? $ar->scopes : array_values(array_intersect($ar->scopes, $scopes));
        $now = $this->now();
        $code = Crypto::token(32);
        $this->stores->codes->saveAuthCode(new AuthorizationCode(
            Crypto::hashToken($code, $this->config->tokenPepper), $ar->client->id, $userId, $ar->redirectUri, $ar->redirectUriProvided,
            $granted, $ar->codeChallenge, $ar->codeChallengeMethod, Crypto::id(), $now + $this->config->authCodeTtl, null, $now,
        ));
        if ($remember) {
            $this->stores->consents->saveConsent(new Consent($userId, $ar->client->id, $granted, $now));
        }
        $params = ['code' => $code];
        if ($ar->state !== null) {
            $params['state'] = $ar->state;
        }
        $params['iss'] = $this->config->issuer;

        return OAuthResponse::redirect(self::appendQuery($ar->redirectUri, $params), $method === 'POST' ? 303 : 302);
    }

    private function errorRedirect(RedirectableException $e, string $method): OAuthResponse
    {
        $params = $e->toArray();
        if ($e->state !== null) {
            $params['state'] = $e->state;
        }
        $params['iss'] = $this->config->issuer;

        return OAuthResponse::redirect(self::appendQuery($e->redirectUri, $params), $method === 'POST' ? 303 : 302);
    }

    /**
     * Exact string match (OAuth 2.1 §2.3.1), except that loopback IP redirect URIs match with any
     * port (§8.4.2, native apps).
     *
     * @param list<string> $registered
     */
    public function redirectUriMatches(string $uri, array $registered): bool
    {
        foreach ($registered as $r) {
            if ($r === $uri) {
                return true;
            }
            $a = parse_url($r);
            $b = parse_url($uri);
            if (is_array($a) && is_array($b) && ($a['scheme'] ?? '') === 'http' && ($b['scheme'] ?? '') === 'http'
                && in_array($a['host'] ?? '', ['127.0.0.1', '[::1]'], true) && ($a['host'] ?? '') === ($b['host'] ?? null)
                && self::withoutPort($r) === self::withoutPort($uri)) {
                return true;
            }
        }

        return false;
    }

    private static function withoutPort(string $uri): string
    {
        return (string) preg_replace('#^(http://(?:127\.0\.0\.1|\[::1\])):\d+#', '$1', $uri);
    }

    /** @param array<string, string> $params */
    public static function appendQuery(string $uri, array $params): string
    {
        return $uri . (str_contains($uri, '?') ? (Str::endsWith($uri, ['?', '&']) ? '' : '&') : '?') . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    // ------------------------------------------------------------------ token endpoint

    public function token(OAuthRequest $request): OAuthResponse
    {
        try {
            if ($request->method !== 'POST') {
                throw OAuthException::invalidRequest('The token endpoint only accepts POST.');
            }
            if (!$request->isForm()) {
                throw OAuthException::invalidRequest('Use application/x-www-form-urlencoded.');
            }
            foreach (array_keys($request->post) as $p) {
                if ($request->isArrayParam((string) $p, 'post')) {
                    throw OAuthException::invalidRequest("Parameter [{$p}] must not be repeated.");
                }
            }
            $grant = $request->param('grant_type', 'post');
            if ($grant === null || $grant === '') {
                throw OAuthException::invalidRequest('Missing grant_type.');
            }
            if (!in_array($grant, self::GRANTS, true)) {
                throw OAuthException::unsupportedGrantType("Grant type [{$grant}] is not supported (OAuth 2.1 removed implicit and password).");
            }
            $client = $this->authenticateClient($request);
            if (!$client->allowsGrant($grant)) {
                throw OAuthException::unauthorizedClient("This client may not use the {$grant} grant.");
            }

            return OAuthResponse::json(match ($grant) {
                'authorization_code' => $this->grantAuthorizationCode($request, $client),
                'refresh_token' => $this->grantRefreshToken($request, $client),
                'client_credentials' => $this->grantClientCredentials($request, $client),
            });
        } catch (OAuthException $e) {
            return $e->toResponse();
        }
    }

    /**
     * Client authentication at the token / revocation / introspection endpoints: client_secret_basic,
     * client_secret_post, or "none" (public client, client_id only). One method per request.
     *
     * @throws OAuthException invalid_client (401) / invalid_request
     */
    public function authenticateClient(OAuthRequest $request): Client
    {
        $basicId = $basicSecret = null;
        $auth = $request->header('authorization');
        if ($auth !== null && preg_match('/^Basic[ ]+([A-Za-z0-9+\/=]+)$/i', trim($auth), $m)) {
            $raw = base64_decode($m[1], true);
            if ($raw === false || !str_contains($raw, ':')) {
                throw OAuthException::invalidClient('Malformed Basic credentials.', ['WWW-Authenticate' => 'Basic realm="' . $this->config->realm . '"']);
            }
            [$u, $p] = explode(':', $raw, 2);
            // RFC 6749 §2.3.1: id and secret are form-urlencoded before Basic encoding
            $basicId = urldecode($u);
            $basicSecret = urldecode($p);
        }
        $postId = $request->param('client_id', 'post');
        $postSecret = $request->param('client_secret', 'post');
        if ($basicId !== null && $postSecret !== null) {
            throw OAuthException::invalidRequest('Use only one client authentication method.');
        }
        if ($basicId !== null && $postId !== null && $postId !== $basicId) {
            throw OAuthException::invalidRequest('client_id does not match the authenticated client.');
        }
        $method = $basicId !== null ? Client::AUTH_BASIC : ($postSecret !== null ? Client::AUTH_POST : Client::AUTH_NONE);
        $clientId = $basicId ?? $postId;
        $challenge = $method === Client::AUTH_BASIC ? ['WWW-Authenticate' => 'Basic realm="' . $this->config->realm . '"'] : [];
        if ($clientId === null || $clientId === '') {
            throw OAuthException::invalidClient('Client authentication failed.', $challenge);
        }
        $client = $this->stores->clients->findClient($clientId);
        if ($method === Client::AUTH_NONE) {
            if ($client === null || $client->isConfidential()) {
                throw OAuthException::invalidClient('Client authentication failed.', $challenge);
            }

            return $client;
        }
        $ok = Crypto::verifySecret((string) ($basicSecret ?? $postSecret), $client?->secretHash);
        if (!$ok || $client === null || ($this->config->strictClientAuthMethod && $client->tokenEndpointAuthMethod !== $method)) {
            throw OAuthException::invalidClient('Client authentication failed.', $challenge);
        }

        return $client;
    }

    /** @return array<string, mixed> */
    private function grantAuthorizationCode(OAuthRequest $request, Client $client): array
    {
        $raw = $request->param('code', 'post');
        if ($raw === null || $raw === '') {
            throw OAuthException::invalidRequest('Missing code.');
        }
        $now = $this->now();
        $hash = Crypto::hashToken($raw, $this->config->tokenPepper);
        $code = $this->stores->codes->findAuthCode($hash);
        if ($code === null || $code->clientId !== $client->id) {
            throw OAuthException::invalidGrant('Invalid authorization code.');
        }
        if ($code->usedAt !== null) {
            // OAuth 2.1 §4.1.3: a reused code SHOULD revoke every token issued from it
            $this->stores->families->revokeFamily($code->familyId, $now, 'code_reuse');
            throw OAuthException::invalidGrant('Authorization code already used; tokens issued from it were revoked.');
        }
        if ($code->isExpired($now)) {
            throw OAuthException::invalidGrant('Authorization code expired.');
        }
        $redirect = $request->param('redirect_uri', 'post');
        if ($code->redirectUriProvided ? $redirect !== $code->redirectUri : ($redirect !== null && $redirect !== $code->redirectUri)) {
            throw OAuthException::invalidGrant('redirect_uri does not match the authorization request.');
        }
        $verifier = $request->param('code_verifier', 'post');
        if ($code->codeChallenge !== '') {
            if ($verifier === null || !Pkce::verify($verifier, $code->codeChallenge, $code->codeChallengeMethod)) {
                throw OAuthException::invalidGrant('PKCE verification failed.');
            }
        } elseif ($verifier !== null) {
            throw OAuthException::invalidGrant('code_verifier sent but no code_challenge was used.');
        }
        if (!$this->stores->codes->consumeAuthCode($hash, $now)) {
            // lost the race against a concurrent exchange of the same code = reuse
            $this->stores->families->revokeFamily($code->familyId, $now, 'code_reuse');
            throw OAuthException::invalidGrant('Authorization code already used; tokens issued from it were revoked.');
        }

        return $this->issue($client, $code->userId, $code->scopes, $code->familyId, $client->allowsGrant('refresh_token'), 'authorization_code');
    }

    /** @return array<string, mixed> */
    private function grantRefreshToken(OAuthRequest $request, Client $client): array
    {
        $raw = $request->param('refresh_token', 'post');
        if ($raw === null || $raw === '') {
            throw OAuthException::invalidRequest('Missing refresh_token.');
        }
        $now = $this->now();
        $hash = Crypto::hashToken($raw, $this->config->tokenPepper);
        $rt = $this->stores->refreshTokens->findRefreshToken($hash);
        if ($rt === null || $rt->clientId !== $client->id) {
            throw OAuthException::invalidGrant('Invalid refresh token.');
        }
        $rotate = !$client->isConfidential() || $this->config->rotateConfidentialRefreshTokens;
        if ($rt->rotatedAt !== null && $rt->revokedAt === null) {
            // a rotated token presented again: stolen or replayed → revoke the whole grant
            $this->stores->families->revokeFamily($rt->familyId, $now, 'refresh_reuse');
            throw OAuthException::invalidGrant('Refresh token reuse detected; the grant was revoked.');
        }
        if ($rt->revokedAt !== null || $this->stores->families->isFamilyRevoked($rt->familyId)) {
            throw OAuthException::invalidGrant('Refresh token revoked.');
        }
        if ($now >= $rt->expiresAt) {
            throw OAuthException::invalidGrant('Refresh token expired.');
        }
        $scopes = $rt->scopes;
        $requested = Scope::parse($request->param('scope', 'post'));
        if ($requested !== []) {
            if (!Scope::subset($requested, $rt->scopes)) {
                throw OAuthException::invalidScope('Requested scope exceeds the original grant.');
            }
            $scopes = $requested;
        }
        if ($rotate && !$this->stores->refreshTokens->rotateRefreshToken($hash, $now)) {
            $this->stores->families->revokeFamily($rt->familyId, $now, 'refresh_reuse');
            throw OAuthException::invalidGrant('Refresh token reuse detected; the grant was revoked.');
        }
        $out = $this->issue($client, $rt->userId, $scopes, $rt->familyId, $rotate, 'refresh_token', $rt->scopes);
        if (!$rotate) {
            $out['refresh_token'] = $raw;
        }

        return $out;
    }

    /** @return array<string, mixed> */
    private function grantClientCredentials(OAuthRequest $request, Client $client): array
    {
        if (!$client->isConfidential()) {
            throw OAuthException::unauthorizedClient('client_credentials requires a confidential client.');
        }
        $scopes = $this->resolveScopes(Scope::parse($request->param('scope', 'post')), $client);

        return $this->issue($client, null, $scopes, Crypto::id(), false, 'client_credentials');
    }

    /**
     * @param list<string> $requested
     * @return list<string>
     */
    private function resolveScopes(array $requested, Client $client): array
    {
        $allowed = $this->config->scopes === [] ? $client->scopes : array_values(array_intersect($client->scopes, $this->config->scopes));
        if ($requested === []) {
            return array_values(array_intersect($this->config->defaultScopes, $allowed));
        }
        if (!Scope::subset($requested, $allowed)) {
            throw OAuthException::invalidScope('Requested scope is not allowed for this client.');
        }

        return $requested;
    }

    /**
     * Mint an access token (+ refresh token) in $familyId.
     *
     * @param list<string> $scopes
     * @param list<string>|null $refreshScopes scopes carried by the new refresh token (default $scopes)
     * @return array<string, mixed>
     */
    private function issue(Client $client, ?string $userId, array $scopes, string $familyId, bool $withRefresh, string $grant, ?array $refreshScopes = null): array
    {
        $now = $this->now();
        $exp = $now + $this->config->accessTokenTtl;
        $jti = Crypto::id();
        if ($this->config->accessTokenFormat === ServerConfig::FORMAT_JWT) {
            $key = $this->config->signingKey ?? throw OAuthException::serverError('No signing key.');
            $claims = ['iss' => $this->config->issuer, 'exp' => $exp, 'aud' => $this->config->audience(), 'sub' => $userId ?? $client->id,
                'client_id' => $client->id, 'iat' => $now, 'jti' => $jti, 'scope' => Scope::format($scopes)];
            if ($grant === 'client_credentials') {
                $claims['gty'] = 'client_credentials';
            }
            $access = Jwt::encode($claims, $key, ['typ' => 'at+jwt']);
            $hash = ResourceServer::jtiHash($jti, $this->config->tokenPepper);
        } else {
            $access = Crypto::token(32);
            $hash = Crypto::hashToken($access, $this->config->tokenPepper);
        }
        $this->stores->accessTokens->saveAccessToken(new AccessToken($hash, $jti, $client->id, $userId, $scopes, $familyId, $now, $exp, null, $this->config->accessTokenFormat));
        $out = ['access_token' => $access, 'token_type' => 'Bearer', 'expires_in' => $this->config->accessTokenTtl, 'scope' => Scope::format($scopes)];
        if ($withRefresh) {
            $refresh = Crypto::token(32);
            $this->stores->refreshTokens->saveRefreshToken(new RefreshToken(Crypto::hashToken($refresh, $this->config->tokenPepper), $client->id, $userId,
                $refreshScopes ?? $scopes, $familyId, $now, $now + $this->config->refreshTokenTtl));
            $out['refresh_token'] = $refresh;
        }

        return $out;
    }

    // ------------------------------------------------------------------ RFC 7009 revocation

    public function revoke(OAuthRequest $request): OAuthResponse
    {
        try {
            if ($request->method !== 'POST' || !$request->isForm()) {
                throw OAuthException::invalidRequest('POST application/x-www-form-urlencoded required.');
            }
            $client = $this->authenticateClient($request);
            $token = $request->param('token', 'post');
            if ($token === null || $token === '') {
                throw OAuthException::invalidRequest('Missing token.');
            }
            $hint = $request->param('token_type_hint', 'post');
            if ($hint !== null && !in_array($hint, ['access_token', 'refresh_token'], true)) {
                throw OAuthException::unsupportedTokenType('token_type_hint must be access_token or refresh_token.');
            }
            $now = $this->now();
            $order = $hint === 'refresh_token' ? ['refresh', 'access'] : ['access', 'refresh'];
            foreach ($order as $kind) {
                if ($kind === 'refresh') {
                    $h = Crypto::hashToken($token, $this->config->tokenPepper);
                    $rt = $this->stores->refreshTokens->findRefreshToken($h);
                    if ($rt !== null) {
                        if ($rt->clientId === $client->id) {
                            // revoking a refresh token invalidates the whole grant (RFC 7009 §2.1)
                            $this->stores->families->revokeFamily($rt->familyId, $now, 'revoked');
                        }
                        break;
                    }
                } else {
                    $at = $this->findAccessTokenRecord($token);
                    if ($at !== null) {
                        if ($at->clientId === $client->id) {
                            $this->stores->accessTokens->revokeAccessToken($at->tokenHash, $now);
                        }
                        break;
                    }
                }
            }

            // RFC 7009 §2.2: 200 whether or not the token existed (no token-existence oracle)
            return new OAuthResponse(200, ['Cache-Control' => 'no-store', 'Content-Type' => 'application/json; charset=utf-8'], '{}');
        } catch (OAuthException $e) {
            return $e->toResponse();
        }
    }

    private function findAccessTokenRecord(string $token): ?AccessToken
    {
        if (Jwt::looksLikeJwt($token) && $this->config->verificationKeys !== []) {
            try {
                [, $c] = Jwt::decode($token, JwkSet::fromSigningKeys(...$this->config->verificationKeys));
            } catch (\Throwable) {
                return null;
            }

            return is_string($c['jti'] ?? null) ? $this->stores->accessTokens->findAccessToken(ResourceServer::jtiHash($c['jti'], $this->config->tokenPepper)) : null;
        }
        $t = $this->stores->accessTokens->findAccessToken(Crypto::hashToken($token, $this->config->tokenPepper));

        return $t !== null && $t->format === ServerConfig::FORMAT_OPAQUE ? $t : null;
    }

    // ------------------------------------------------------------------ RFC 7662 introspection

    /**
     * Confidential clients only. A client sees its own tokens; clients registered with
     * canIntrospect (resource servers) see every token of this issuer. Anything else: active=false.
     */
    public function introspect(OAuthRequest $request): OAuthResponse
    {
        try {
            if ($request->method !== 'POST' || !$request->isForm()) {
                throw OAuthException::invalidRequest('POST application/x-www-form-urlencoded required.');
            }
            $caller = $this->authenticateClient($request);
            if (!$caller->isConfidential()) {
                throw OAuthException::invalidClient('Introspection requires client authentication.');
            }
            $token = $request->param('token', 'post');
            if ($token === null || $token === '') {
                throw OAuthException::invalidRequest('Missing token.');
            }
            $hint = $request->param('token_type_hint', 'post');
            $now = $this->now();
            $result = null;
            foreach ($hint === 'refresh_token' ? ['refresh', 'access'] : ['access', 'refresh'] as $kind) {
                $result = $kind === 'access' ? $this->introspectAccess($token, $now) : $this->introspectRefresh($token, $now);
                if ($result !== null) {
                    break;
                }
            }
            if ($result === null || (!$caller->canIntrospect && $result['client_id'] !== $caller->id)) {
                return OAuthResponse::json(['active' => false]);
            }

            return OAuthResponse::json($result);
        } catch (OAuthException $e) {
            return $e->toResponse();
        }
    }

    /** @return array<string, mixed>|null */
    private function introspectAccess(string $token, int $now): ?array
    {
        try {
            $i = $this->resourceServer()->validate($token, $now);
        } catch (OAuthException) {
            return null;
        }
        $out = ['active' => true, 'scope' => Scope::format($i->scopes), 'client_id' => $i->clientId, 'token_type' => 'Bearer',
            'exp' => $i->expiresAt, 'iat' => $i->issuedAt, 'sub' => $i->subject(), 'aud' => $this->config->audience(), 'iss' => $this->config->issuer, 'jti' => $i->jti];
        if ($i->userId !== null) {
            $out['username'] = $i->userId;
        }

        return $out;
    }

    /** @return array<string, mixed>|null */
    private function introspectRefresh(string $token, int $now): ?array
    {
        $rt = $this->stores->refreshTokens->findRefreshToken(Crypto::hashToken($token, $this->config->tokenPepper));
        if ($rt === null || $rt->revokedAt !== null || $rt->rotatedAt !== null || $now >= $rt->expiresAt || $this->stores->families->isFamilyRevoked($rt->familyId)) {
            return null;
        }

        return ['active' => true, 'scope' => Scope::format($rt->scopes), 'client_id' => $rt->clientId, 'token_type' => 'refresh_token',
            'exp' => $rt->expiresAt, 'iat' => $rt->issuedAt, 'sub' => $rt->userId ?? $rt->clientId, 'iss' => $this->config->issuer];
    }

    // ------------------------------------------------------------------ RFC 8414 metadata + JWKS

    /** @return array<string, mixed> */
    public function metadata(): array
    {
        $m = [
            'issuer' => $this->config->issuer,
            'authorization_endpoint' => $this->config->endpoint('authorization'),
            'token_endpoint' => $this->config->endpoint('token'),
            'revocation_endpoint' => $this->config->endpoint('revocation'),
            'introspection_endpoint' => $this->config->endpoint('introspection'),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => self::GRANTS,
            'token_endpoint_auth_methods_supported' => [Client::AUTH_BASIC, Client::AUTH_POST, Client::AUTH_NONE],
            'revocation_endpoint_auth_methods_supported' => [Client::AUTH_BASIC, Client::AUTH_POST, Client::AUTH_NONE],
            'introspection_endpoint_auth_methods_supported' => [Client::AUTH_BASIC, Client::AUTH_POST],
            'code_challenge_methods_supported' => $this->config->allowPlainPkce ? [Pkce::S256, Pkce::PLAIN] : [Pkce::S256],
            'authorization_response_iss_parameter_supported' => true,
        ];
        if ($this->config->scopes !== []) {
            $m['scopes_supported'] = $this->config->scopes;
        }
        if ($this->config->verificationKeys !== []) {
            $m['jwks_uri'] = $this->config->endpoint('jwks');
        }

        return $m;
    }

    public function metadataResponse(): OAuthResponse
    {
        return new OAuthResponse(200, ['Content-Type' => 'application/json; charset=utf-8', 'Cache-Control' => 'public, max-age=300'],
            (string) json_encode($this->metadata(), JSON_UNESCAPED_SLASHES));
    }

    /** RFC 8414 §3: /.well-known/oauth-authorization-server + the issuer's path component. */
    public function metadataPath(): string
    {
        $path = rtrim((string) (parse_url($this->config->issuer, PHP_URL_PATH) ?? ''), '/');

        return '/.well-known/oauth-authorization-server' . $path;
    }

    /** @return array{keys: list<array<string, mixed>>} */
    public function jwks(): array
    {
        return JwkSet::fromSigningKeys(...$this->config->verificationKeys)->toArray();
    }

    public function jwksResponse(): OAuthResponse
    {
        return new OAuthResponse(200, ['Content-Type' => 'application/jwk-set+json', 'Cache-Control' => 'public, max-age=300'],
            (string) json_encode($this->jwks(), JSON_UNESCAPED_SLASHES));
    }
}
