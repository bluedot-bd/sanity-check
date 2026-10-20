<?php

namespace BluedotBd\SanityCheck\Support;

use Composer\Semver\Semver;
use Illuminate\Support\Facades\Http;
use RuntimeException;
use Throwable;

/**
 * Client for https://packagist.org/api/security-advisories/?packages[]=vendor/package
 */
class AdvisoryClient
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
     * @return array{findings: array<int, array<string, string>>, errors: array<int, string>, checked: int}
     */
    public function find(array $packages, array $ignore = []): array
    {
        $findings = [];
        $errors = [];
        $checked = 0;
        $batchSize = max(1, (int) ($this->config['batch_size'] ?? 50));

        foreach (array_chunk($packages, $batchSize, true) as $batch) {
            $checked += count($batch);

            try {
                $advisories = $this->fetch(array_keys($batch));
            } catch (Throwable $e) {
                $errors[] = $e->getMessage();

                continue;
            }

            $findings = array_merge($findings, self::filter($advisories, $batch, $ignore));
        }

        return ['findings' => $findings, 'errors' => $errors, 'checked' => $checked];
    }

    /**
     * Keep the advisories that actually affect the installed version.
     *
     * @param  array<string, mixed>  $advisories  the "advisories" map of the API response
     * @param  array<string, string>  $packages  name => installed version
     * @param  array<int, string>  $ignore
     * @return array<int, array<string, string>>
     */
    public static function filter(array $advisories, array $packages, array $ignore = []): array
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

                $id = (string) ($advisory['advisoryId'] ?? '');

                if ($id !== '' && in_array($id, $ignore, true)) {
                    continue;
                }

                if (! self::isAffected($packages[$package], (string) ($advisory['affectedVersions'] ?? ''))) {
                    continue;
                }

                $sources = (array) ($advisory['sources'] ?? []);
                $sourceId = is_array($sources[0] ?? null) ? (string) ($sources[0]['remoteId'] ?? '') : '';

                $findings[] = [
                    'package' => $package,
                    'version' => $packages[$package],
                    'advisory_id' => $id,
                    'cve' => (string) ($advisory['cve'] ?? '') ?: $sourceId,
                    'title' => (string) ($advisory['title'] ?? ''),
                    'affected' => (string) ($advisory['affectedVersions'] ?? ''),
                    'link' => (string) ($advisory['link'] ?? ''),
                ];
            }
        }

        return $findings;
    }

    public static function isAffected(string $version, string $constraint): bool
    {
        if ($version === '' || trim($constraint) === '') {
            return false;
        }

        try {
            return Semver::satisfies($version, $constraint);
        } catch (Throwable $e) {
            return false;
        }
    }

    /**
     * @param  array<int, string>  $names
     * @return array<string, mixed>
     */
    private function fetch(array $names): array
    {
        if ($names === []) {
            return [];
        }

        $base = (string) ($this->config['url'] ?? 'https://packagist.org/api/security-advisories/');
        $query = implode('&', array_map(fn (string $name) => 'packages[]=' . rawurlencode($name), $names));
        $separator = str_contains($base, '?') ? '&' : '?';

        $response = Http::timeout((int) ($this->config['timeout'] ?? 10))
            ->acceptJson()
            ->get($base . $separator . $query);

        if (! $response->successful()) {
            throw new RuntimeException("Packagist advisories API returned HTTP {$response->status()}.");
        }

        return (array) ($response->json('advisories') ?? []);
    }
}