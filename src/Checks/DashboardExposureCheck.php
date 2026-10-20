<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;
use BluedotBd\SanityCheck\Support\ProbeClient;
use Studio\Totem\Totem;

class DashboardExposureCheck extends Check
{
    public function __construct(private ProbeClient $probe)
    {
    }

    public function key(): string
    {
        return 'dashboards';
    }

    public function label(): string
    {
        return 'Admin dashboards';
    }

    public function run(): Result
    {
        if ($this->probe->skipRemote()) {
            return $this->pass('Remote probes are disabled.');
        }

        $targets = $this->targets();

        if ($targets === []) {
            return $this->pass('No admin dashboard is installed.');
        }

        $exposed = [];
        $unclear = [];
        $problems = [];
        $protected = [];

        foreach ($targets as $label => $target) {
            $response = $this->probe->fetch($target['url']);

            if ($response['error'] !== null) {
                $problems[] = "{$target['url']} ({$response['error']})";

                continue;
            }

            if ($response['status'] !== 200) {
                $protected[] = "{$label} HTTP {$response['status']}";

                continue;
            }

            $signature = $target['signature'];

            if ($signature !== null && preg_match($signature, substr($response['body'], 0, 8192)) === 1) {
                $exposed[] = $target['url'];

                continue;
            }

            $unclear[] = $target['url'];
        }

        if ($exposed !== []) {
            return $this->fail('Anonymous access allowed: ' . implode(', ', $exposed));
        }

        if ($unclear !== []) {
            return $this->warn('HTTP 200 without dashboard markup, verify manually: ' . implode(', ', $unclear));
        }

        if ($problems !== []) {
            return $this->warn('Probe failed: ' . implode('; ', $problems));
        }

        return $this->pass('Protected (' . implode(', ', $protected) . ').');
    }

    /**
     * @return array<string, array{url: string, signature: ?string}>
     */
    private function targets(): array
    {
        $targets = [];

        foreach ((array) config('sanity-check.checks.dashboards.targets', []) as $key => $target) {
            if (! ($target['enabled'] ?? true) || ! $this->isInstalled((string) $key)) {
                continue;
            }

            $url = $this->resolveUrl((string) $key, (string) ($target['path'] ?? $key));

            if ($url === null) {
                continue;
            }

            $targets[(string) ($target['label'] ?? ucfirst((string) $key))] = [
                'url' => $url,
                'signature' => $target['signature'] ?? null,
            ];
        }

        return $targets;
    }

    private function isInstalled(string $key): bool
    {
        return match ($key) {
            'horizon' => class_exists(\Laravel\Horizon\Horizon::class),
            'totem' => class_exists(Totem::class),
            'telescope' => class_exists(\Laravel\Telescope\Telescope::class),
            default => false,
        };
    }

    private function resolveUrl(string $key, string $path): ?string
    {
        $path = trim($path, '/');

        if ($key === 'horizon' && ($domain = config('horizon.domain'))) {
            $scheme = parse_url((string) $this->probe->baseUrl(), PHP_URL_SCHEME) ?: 'https';

            return $scheme . '://' . $domain . '/' . $path;
        }

        return $this->probe->url($path);
    }
}