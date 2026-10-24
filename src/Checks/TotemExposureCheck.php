<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;
use BluedotBd\SanityCheck\Support\ProbeClient;
use Studio\Totem\Totem;

/**
 * The Totem dashboard can schedule and run arbitrary artisan commands, so a
 * publicly readable Totem is treated as an emergency (see the maintenance
 * action's "trigger_on" list).
 */
class TotemExposureCheck extends Check
{
    public const DEFAULT_SIGNATURE = '~vendor/totem/css/app\.css|<title>\s*Totem~i';

    public function __construct(private ProbeClient $probe)
    {
    }

    public function key(): string
    {
        return 'totem_exposure';
    }

    public function label(): string
    {
        return 'Totem exposure';
    }

    public function run(): Result
    {
        if (! class_exists(Totem::class)) {
            return $this->pass('Totem is not installed.');
        }

        if ($this->probe->skipRemote()) {
            return $this->pass('Remote probes are disabled.');
        }

        $url = $this->probe->url($this->path(), $this->domain());

        if ($url === null) {
            return $this->warn('APP_URL is not configured - Totem probe skipped.');
        }

        $response = $this->probe->fetch($url);

        if ($response['error'] !== null) {
            return $this->warn("Could not probe {$url}: {$response['error']}");
        }

        if ($response['status'] !== 200) {
            return $this->pass("Totem is not publicly readable (HTTP {$response['status']}).");
        }

        $signature = (string) config('sanity-check.checks.totem_exposure.signature', self::DEFAULT_SIGNATURE);

        if (self::bodyLooksLikeTotem($response['body'], $signature)) {
            return $this->fail("{$url} is readable without authentication.");
        }

        return $this->warn("{$url} returned HTTP 200 without Totem markup - verify manually.");
    }

    public static function bodyLooksLikeTotem(string $body, ?string $signature = null): bool
    {
        $signature = $signature ?: self::DEFAULT_SIGNATURE;

        return @preg_match($signature, substr($body, 0, 8192)) === 1;
    }

    /**
     * Totem's URI comes from its own config, so a custom route_prefix is
     * probed as deployed instead of the default "totem".
     */
    private function path(): string
    {
        $override = config('sanity-check.checks.totem_exposure.path');

        if (is_string($override) && trim($override) !== '') {
            return trim($override, '/');
        }

        return trim((string) config('totem.web.route_prefix', 'totem'), '/');
    }

    /**
     * Totem is served from TOTEM_ALLOWED_HOSTS (falling back to ADMIN_DOMAIN),
     * so that is the host to probe. APP_URL is normally a different domain, and
     * its 404 would read as "not exposed".
     */
    private function domain(): ?string
    {
        $override = config('sanity-check.checks.totem_exposure.domain');

        if (is_string($override) && trim($override) !== '') {
            return $override;
        }

        return config('totem.allowed_hosts') ?: config('app.admin_domain');
    }
}