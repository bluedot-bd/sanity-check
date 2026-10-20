<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;
use BluedotBd\SanityCheck\Support\ProbeClient;

class DebugbarCheck extends Check
{
    public function __construct(private ProbeClient $probe)
    {
    }

    public function key(): string
    {
        return 'debugbar';
    }

    public function label(): string
    {
        return 'Debugbar';
    }

    public function run(): Result
    {
        $installed = class_exists(\Barryvdh\Debugbar\Facades\Debugbar::class)
            || class_exists(\Barryvdh\Debugbar\ServiceProvider::class);

        if (! $installed) {
            return $this->pass('Debugbar is not installed.');
        }

        $enabled = config('debugbar.enabled');

        if ($enabled === null) {
            $enabled = (bool) config('app.debug');
        }

        if ($enabled) {
            if (! $this->isProduction()) {
                return $this->pass('Debugbar is enabled (non-production).');
            }

            return $this->fail('Debugbar is enabled in production - request data, queries and config become inspectable.');
        }

        $exposed = $this->probeOpenHandler();

        if ($exposed !== null) {
            return $this->fail("{$exposed} is reachable even though debugbar is disabled.");
        }

        return $this->pass('Debugbar is installed but disabled.');
    }

    private function probeOpenHandler(): ?string
    {
        if ($this->probe->skipRemote()) {
            return null;
        }

        $url = $this->probe->url((string) config('sanity-check.checks.debugbar.path', '_debugbar/open'));

        if ($url === null) {
            return null;
        }

        $response = $this->probe->fetch($url);
        $body = substr($response['body'], 0, 4096);

        if ($response['status'] === 200 && preg_match('~"__meta"\s*:~', $body) === 1) {
            return $url;
        }

        return null;
    }
}