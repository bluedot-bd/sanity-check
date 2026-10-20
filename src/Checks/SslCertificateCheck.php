<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;
use BluedotBd\SanityCheck\Support\ProbeClient;

class SslCertificateCheck extends Check
{
    public function __construct(private ProbeClient $probe)
    {
    }

    public function key(): string
    {
        return 'ssl';
    }

    public function label(): string
    {
        return 'TLS certificate';
    }

    public function run(): Result
    {
        $base = $this->probe->baseUrl();

        if ($base === null) {
            return $this->warn('APP_URL is not configured - certificate check skipped.');
        }

        if (! str_starts_with($base, 'https://')) {
            return $this->productionIssue('APP_URL is not HTTPS - there is no certificate to inspect.');
        }

        $host = (string) parse_url($base, PHP_URL_HOST);
        $port = (int) (parse_url($base, PHP_URL_PORT) ?: 443);

        if ($host === '') {
            return $this->warn('Could not determine the host of APP_URL.');
        }

        $certificate = $this->certificate($host, $port);

        if ($certificate === null) {
            return $this->warn("Could not read the TLS certificate of {$host}:{$port}.");
        }

        $expiresAt = (int) ($certificate['validTo_time_t'] ?? 0);

        if ($expiresAt === 0) {
            return $this->warn("The certificate of {$host} has no expiry date to inspect.");
        }

        $days = self::daysUntil($expiresAt, time());
        $warnDays = (int) config('sanity-check.checks.ssl.warn_days', 3);
        $expiresOn = date('Y-m-d', $expiresAt);

        return match (self::verdict($days, $warnDays)) {
            Result::FAIL => $this->fail("Certificate for {$host} expired on {$expiresOn} ({$days} days)."),
            Result::WARN => $this->warn("Certificate for {$host} expires on {$expiresOn}, in {$days} day(s)."),
            default => $this->pass("Certificate for {$host} is valid until {$expiresOn} ({$days} days)."),
        };
    }

    /**
     * Whole days until the certificate expires (negative when already expired).
     */
    public static function daysUntil(int $expiresAt, ?int $now = null): int
    {
        return (int) floor(($expiresAt - ($now ?? time())) / 86400);
    }

    /**
     * @return string one of the Result status constants
     */
    public static function verdict(int $days, int $warnDays): string
    {
        if ($days < 0) {
            return Result::FAIL;
        }

        return $days <= $warnDays ? Result::WARN : Result::PASS;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function certificate(string $host, int $port): ?array
    {
        if (! function_exists('openssl_x509_parse')) {
            return null;
        }

        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => (bool) config('sanity-check.checks.ssl.verify_peer', true),
                'verify_peer_name' => (bool) config('sanity-check.checks.ssl.verify_peer', true),
                'SNI_enabled' => true,
                'peer_name' => $host,
            ],
        ]);

        $client = @stream_socket_client(
            "ssl://{$host}:{$port}",
            $errorCode,
            $errorMessage,
            5,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($client === false) {
            return null;
        }

        $params = stream_context_get_params($client);
        fclose($client);

        $peer = $params['options']['ssl']['peer_certificate'] ?? null;

        if ($peer === null) {
            return null;
        }

        $parsed = openssl_x509_parse($peer);

        return is_array($parsed) ? $parsed : null;
    }
}