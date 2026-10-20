<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;

class NightwatchCheck extends Check
{
    public function key(): string
    {
        return 'nightwatch';
    }

    public function label(): string
    {
        return 'Nightwatch';
    }

    public function run(): Result
    {
        if (! class_exists(\Laravel\Nightwatch\Nightwatch::class)) {
            return $this->pass('Nightwatch is not installed.');
        }

        if (! $this->isProduction()) {
            return $this->pass('Nightwatch is installed (non-production).');
        }

        if (! config('nightwatch.enabled')) {
            return $this->warn('Nightwatch is installed but disabled in production - no request monitoring.');
        }

        $token = (string) (config('nightwatch.token') ?: env('NIGHTWATCH_TOKEN') ?: '');

        if ($token === '') {
            return $this->fail('Nightwatch is enabled but the token (NIGHTWATCH_TOKEN) is missing.');
        }

        return $this->pass('Nightwatch is enabled with a token.');
    }
}