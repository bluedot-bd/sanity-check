<?php

namespace BluedotBd\SanityCheck\Support;

use Composer\Semver\Semver;
use Illuminate\Support\Facades\Http;
use RuntimeException;
use Throwable;

/**
 * Client for https://registry.npmjs.org/-/npm/v1/security/advisories/bulk
 * (the endpoint behind "npm audit").
 */
class NpmAdvisoryClient
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(private array $config = [])
    {
    }

    /**
     * @param  array<string, string>  $packages  name => installed version
     * @param  array<int, string>  $ignore  advisory ids to skip
     * @param  array<int, string>  $severities  severities to report
     * @return array{findings: array<int, array<string, string>>, errors: array<int, string>, checked: int}
     */
    public function find(array $packages, array $ignore = [], array $severities = []): array
    {
        $findings = [];
        $errors = [];
        $checked = 0;
        $batchSize = max(1, (int) ($this->config['batch_size'] ?? 50));

        foreach (array_chunk($packages, $batchSize, true) as $batch) {
            $checked += count($batch);

            try {
                $advisories = $this->fetch($batch);
            } catch (Throwable $e) {
                $errors[] = $e->getMessage();

                continue;
            }

            $findings = array_merge($findings, self::filter($advisories, $batch, $ignore, $severities));
        }

        usort($findings, fn (array $a, array $b) => self::severityRank($a['severity']) <=> self::severityRank($b['severity']));

        return ['findings' => $findings, 'errors' => $errors, 'checked' => $checked];
    }

    /**
     * Keep the advisories that affect the installed version.
     *
     * @param  array<string, mixed>  $advisories  the API response (package => advisories)
     * @param  array<string, string>  $packages  name => installed version
     * @param  array<int, string>  $ignore
     * @param  array<int, string>  $severities
     * @return array<int, array<string, string>>
     */
    public static function filter(array $advisories, array $packages, array $ignore = [], array $severities = []): array
    {
        $findings = [];

        foreach ($advisories as $package => $entries) {
            $package = (string) $package;

            if (! isset($packages[$package])) {
                continue;
            }

            foreach ((array) $entries as $advisory) {
                if (! is_array($advisory)) {
                    continue;
                }

                $id = (string) ($advisory['id'] ?? '');

                if ($id !== '' && in_array($id, $ignore, true)) {
                    continue;
                }

                $severity = strtolower((string) ($advisory['severity'] ?? 'unknown'));

                if ($severities !== [] && ! in_array($severity, $severities, true)) {
                    continue;
                }

                if (! self::isVulnerable($packages[$package], (string) ($advisory['vulnerable_versions'] ?? ''))) {
                    continue;
                }

                $findings[] = [
                    'package' => $package,
                    'version' => $packages[$package],
                    'advisory_id' => $id,
                    'severity' => $severity,
                    'title' => (string) ($advisory['title'] ?? ''),
                    'vulnerable' => (string) ($advisory['vulnerable_versions'] ?? ''),
                    'url' => (string) ($advisory['url'] ?? ''),
                    'cwe' => implode(', ', (array) ($advisory['cwe'] ?? [])),
                ];
            }
        }

        usort($findings, fn (array $a, array $b) => self::severityRank($a['severity']) <=> self::severityRank($b['severity']));

        return $findings;
    }

    public static function isVulnerable(string $version, string $range): bool
    {
        if ($version === '' || trim($range) === '') {
            return false;
        }

        try {
            return Semver::satisfies($version, $range);
        } catch (Throwable $e) {
            return false;
        }
    }

    public static function severityRank(string $severity): int
    {
        return match (strtolower($severity)) {
            'critical' => 0,
            'high' => 1,
            'moderate', 'medium' => 2,
            'low' => 3,
            default => 4,
        };
    }

    /**
     * @param  array<string, string>  $batch  name => version
     * @return array<string, mixed>
     */
    private function fetch(array $batch): array
    {
        if ($batch === []) {
            return [];
        }

        $payload = [];

        foreach ($batch as $name => $version) {
            $payload[$name] = [$version];
        }

        $url = (string) ($this->config['url'] ?? 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk');

        $response = Http::timeout((int) ($this->config['timeout'] ?? 15))
            ->acceptJson()
            ->asJson()
            ->post($url, $payload);

        if (! $response->successful()) {
            throw new RuntimeException("npm advisories API returned HTTP {$response->status()}.");
        }

        return (array) $response->json();
    }
}