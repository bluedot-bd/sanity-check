<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;
use BluedotBd\SanityCheck\Support\ProbeClient;

class LogViewerCheck extends Check
{
    public function __construct(private ProbeClient $probe)
    {
    }

    public function key(): string
    {
        return 'log_viewer';
    }

    public function label(): string
    {
        return 'Log viewer';
    }

    public function run(): Result
    {
        if (! class_exists(\Opcodes\LogViewer\LogViewerServiceProvider::class)) {
            return $this->pass('Log viewer is not installed.');
        }

        $enabled = config('log-viewer.enabled');
        $enabled = $enabled === null ? true : (bool) $enabled;

        if ($this->probe->skipRemote()) {
            return $enabled
                ? $this->warn('Log viewer is enabled - remote exposure probe skipped.')
                : $this->pass('Log viewer is disabled.');
        }

        $url = $this->probe->url($this->path());

        if ($url === null) {
            return $this->warn('APP_URL is not configured - log viewer probe skipped.');
        }

        $response = $this->probe->fetch($url);

        if ($response['error'] !== null) {
            return $this->warn("Could not probe {$url}: {$response['error']}");
        }

        if ($response['status'] !== 200) {
            return $enabled
                ? $this->pass("Log viewer is enabled but protected (HTTP {$response['status']}).")
                : $this->pass('Log viewer is disabled.');
        }

        $signature = (string) config('sanity-check.checks.log_viewer.signature', '~log-viewer|Log Viewer~i');

        if (preg_match($signature, substr($response['body'], 0, 8192)) === 1) {
            return $this->fail("{$url} is readable without authentication.");
        }

        return $this->warn("{$url} returned HTTP 200 without log viewer markup - verify manually.");
    }

    private function path(): string
    {
        $configured = config('log-viewer.route_path');

        return trim((string) ($configured ?: config('sanity-check.checks.log_viewer.path', 'log-viewer')), '/');
    }
}