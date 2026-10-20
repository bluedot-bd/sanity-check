<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;

class DebugModeCheck extends Check
{
    public function key(): string
    {
        return 'debug';
    }

    public function label(): string
    {
        return 'Debug mode';
    }

    public function run(): Result
    {
        if (! config('app.debug')) {
            return $this->pass('APP_DEBUG is off.');
        }

        $environment = app()->environment();

        if (app()->environment(['local', 'testing'])) {
            return $this->pass("APP_DEBUG is on ({$environment} environment).");
        }

        return $this->fail("APP_DEBUG is on ({$environment}) - stack traces and environment values may leak.");
    }
}