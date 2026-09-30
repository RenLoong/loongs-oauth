<?php

declare(strict_types=1);

namespace Loongs\OAuth\Authorization;

use Loongs\OAuth\Entity\Client;

/** A validated authorization request (client, exact redirect URI, scopes, PKCE, state). */
final readonly class AuthorizationRequest
{
    /** @param list<string> $scopes */
    public function __construct(
        public Client $client,
        public string $redirectUri,
        public bool $redirectUriProvided,
        public array $scopes,
        public ?string $state,
        public string $codeChallenge,
        public string $codeChallengeMethod,
    ) {
    }

    /**
     * The request parameters, e.g. for hidden fields of a login / consent form that posts back to the
     * authorization endpoint.
     *
     * @return array<string, string>
     */
    public function parameters(): array
    {
        $p = ['response_type' => 'code', 'client_id' => $this->client->id];
        if ($this->redirectUriProvided) {
            $p['redirect_uri'] = $this->redirectUri;
        }
        if ($this->scopes !== []) {
            $p['scope'] = implode(' ', $this->scopes);
        }
        if ($this->state !== null) {
            $p['state'] = $this->state;
        }
        $p['code_challenge'] = $this->codeChallenge;
        $p['code_challenge_method'] = $this->codeChallengeMethod;

        return $p;
    }
}
