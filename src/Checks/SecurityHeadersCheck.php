<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;
use BluedotBd\SanityCheck\Support\ProbeClient;

class SecurityHeadersCheck extends Check
{
    /**
     * Human readable names for the headers we audit.
     *
     * @var array<string, string>
     */
    private const NAMES = [
        'x-frame-options' => 'X-Frame-Options',
        'x-content-type-options' => 'X-Content-Type-Options',
        'content-security-policy' => 'Content-Security-Policy',
        'strict-transport-security' => 'Strict-Transport-Security',
        'referrer-policy' => 'Referrer-Policy',
        'permissions-policy' => 'Permissions-Policy',
    ];

    public function __construct(private ProbeClient $probe)
    {
    }

    public function key(): string
    {
        return 'security_headers';
    }

    public function label(): string
    {
        return 'Security headers';
    }

    public function run(): Result
    {
        if ($this->probe->skipRemote()) {
            return $this->pass('Remote probes are disabled.');
        }

        $base = $this->probe->baseUrl();

        if ($base === null) {
            return $this->warn('APP_URL is not configured - header probe skipped.');
        }

        $response = $this->probe->fetch($base, true);

        if ($response['error'] !== null) {
            return $this->warn("Could not fetch {$base}: {$response['error']}");
        }

        $required = (array) config('sanity-check.checks.security_headers.required', []);
        $missing = self::missingHeaders($response['headers'], $required, $this->probe->isHttps());

        if ($missing !== []) {
            return $this->warn('Missing: ' . implode(', ', $missing) . '.');
        }

        return $this->pass('All required headers are present.');
    }

    /**
     * @param  array<string, array<int, string>>  $headers  header names => values (case insensitive)
     * @param  array<int, string>  $required
     * @return array<int, string>
     */
    public static function missingHeaders(array $headers, array $required, bool $https): array
    {
        $normalized = [];

        foreach ($headers as $name => $values) {
            $normalized[strtolower((string) $name)] = array_map('strval', (array) $values);
        }

        $csp = $normalized['content-security-policy'] ?? [];
        $missing = [];

        foreach ($required as $header) {
            $header = strtolower((string) $header);

            if ($header === 'strict-transport-security' && ! $https) {
                continue;
            }

            if ($header === 'x-frame-options' && self::hasFrameAncestors($csp)) {
                continue;
            }

            if ($header === 'x-content-type-options' && self::hasValue($normalized[$header] ?? [], 'nosniff')) {
                continue;
            }

            if (($normalized[$header] ?? []) !== []) {
                continue;
            }

            $missing[] = self::NAMES[$header] ?? $header;
        }

        return $missing;
    }

    /**
     * @param  array<int, string>  $values
     */
    private static function hasValue(array $values, string $needle): bool
    {
        foreach ($values as $value) {
            if (stripos($value, $needle) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<int, string>  $csp
     */
    private static function hasFrameAncestors(array $csp): bool
    {
        return self::hasValue($csp, 'frame-ancestors');
    }
}