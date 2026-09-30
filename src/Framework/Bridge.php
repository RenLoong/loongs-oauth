<?php

declare(strict_types=1);

namespace Loongs\OAuth\Framework;

use Loongs\Http\Request;
use Loongs\Http\Response;
use Loongs\OAuth\Http\OAuthRequest;
use Loongs\OAuth\Http\OAuthResponse;

/** loongs/framework Request / Response ↔ OAuthRequest / OAuthResponse. */
final class Bridge
{
    public static function request(Request $r): OAuthRequest
    {
        return new OAuthRequest($r->method(), $r->headers(), $r->queryAll(), $r->postAll(), $r->body());
    }

    public static function response(OAuthResponse $o): Response
    {
        $res = (new Response())->status($o->status);
        $res->raw($o->body, $o->header('Content-Type') ?? 'text/plain; charset=utf-8');
        foreach ($o->headers as $k => $v) {
            if (strcasecmp($k, 'Content-Type') !== 0) {
                $res->header($k, $v);
            }
        }

        return $res;
    }
}
