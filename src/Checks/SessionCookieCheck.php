<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;

class SessionCookieCheck extends Check
{
    public function key(): string
    {
        return 'session';
    }

    public function label(): string
    {
        return 'Session cookies';
    }

    public function run(): Result
    {
        $issues = [];

        if (! config('session.http_only', true)) {
            $issues[] = 'http_only is off';
        }

        if (config('session.same_site') === null) {
            $issues[] = 'same_site is not set';
        }

        if (! config('session.secure')) {
            $issues[] = 'secure is off';
        }

        if ($issues !== []) {
            return $this->productionIssue(implode(', ', $issues) . '.');
        }

        return $this->pass('Secure, HttpOnly and SameSite are enabled.');
    }
}