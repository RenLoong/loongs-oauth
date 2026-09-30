<?php

declare(strict_types=1);

namespace Loongs\OAuth\Support;

use Loongs\OAuth\Exception\OAuthException;

/** Scope strings (RFC 6749 §3.3): space-delimited, case-sensitive scope-tokens of %x21 / %x23-5B / %x5D-7E. */
final class Scope
{
    /**
     * @return list<string> unique, order kept
     * @throws OAuthException invalid_scope on a malformed scope-token
     */
    public static function parse(?string $scope): array
    {
        if ($scope === null || trim($scope, ' ') === '') {
            return [];
        }
        $out = [];
        foreach (explode(' ', $scope) as $s) {
            if ($s === '') {
                continue;
            }
            if (!preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/D', $s)) {
                throw OAuthException::invalidScope('Malformed scope value.');
            }
            $out[$s] = true;
        }

        return array_keys($out);
    }

    /** @param list<string> $scopes */
    public static function format(array $scopes): string
    {
        return implode(' ', $scopes);
    }

    /** @param list<string> $scopes @param list<string> $allowed */
    public static function subset(array $scopes, array $allowed): bool
    {
        return array_diff($scopes, $allowed) === [];
    }
}
