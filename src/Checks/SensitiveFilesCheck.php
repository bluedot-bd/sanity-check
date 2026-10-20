<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;
use BluedotBd\SanityCheck\Support\ProbeClient;

class SensitiveFilesCheck extends Check
{
    public function __construct(private ProbeClient $probe)
    {
    }

    public function key(): string
    {
        return 'sensitive_files';
    }

    public function label(): string
    {
        return 'Public files';
    }

    public function run(): Result
    {
        if ($this->probe->skipRemote()) {
            return $this->pass('Remote probes are disabled.');
        }

        if ($this->probe->baseUrl() === null) {
            return $this->warn('APP_URL is not configured - file probes skipped.');
        }

        $exposed = [];
        $optional = [];
        $errors = 0;

        foreach ((array) config('sanity-check.checks.sensitive_files.paths', []) as $path => $signature) {
            $match = $this->probePath((string) $path, $signature);

            if ($match !== null) {
                $exposed[] = $match;
            }
        }

        foreach ((array) config('sanity-check.checks.sensitive_files.optional_paths', []) as $path => $signature) {
            $match = $this->probePath((string) $path, $signature);

            if ($match !== null) {
                $optional[] = $match;
            }
        }

        if ($exposed !== []) {
            return $this->fail('Accessible: ' . implode(', ', $exposed));
        }

        if ($optional !== []) {
            return $this->warn('Responding but not confirmed: ' . implode(', ', $optional));
        }

        return $this->pass('No sensitive file is downloadable.');
    }

    private function probePath(string $path, ?string $signature): ?string
    {
        $url = $this->probe->url($path);

        if ($url === null) {
            return null;
        }

        $response = $this->probe->fetch($url);

        if ($response['error'] !== null || $response['status'] !== 200) {
            return null;
        }

        $body = substr($response['body'], 0, 8192);

        if ($signature === null) {
            return EnvFileExposureCheck::bodyLooksLikeEnvFile($body) ? $url : null;
        }

        return preg_match($signature, $body) === 1 ? $url : null;
    }
}