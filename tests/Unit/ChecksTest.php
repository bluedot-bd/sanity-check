<?php

namespace BluedotBd\SanityCheck\Tests\Unit;

use BluedotBd\SanityCheck\Checks\DomainEnvironmentCheck;
use BluedotBd\SanityCheck\Checks\EnvFileExposureCheck;
use BluedotBd\SanityCheck\Checks\SecurityHeadersCheck;
use BluedotBd\SanityCheck\Checks\SslCertificateCheck;
use BluedotBd\SanityCheck\Report;
use BluedotBd\SanityCheck\Results\Result;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ChecksTest extends TestCase
{
    private const REQUIRED_HEADERS = [
        'x-frame-options',
        'x-content-type-options',
        'content-security-policy',
        'strict-transport-security',
    ];

    public static function envLikeBodies(): array
    {
        return [
            'laravel env' => ["APP_NAME=\"App\"\nAPP_ENV=production\nAPP_KEY=base64:q1w2e3r4=\nDB_CONNECTION=mysql\n"],
            'indented keys' => ["  APP_KEY=base64:q1w2e3r4=\n  APP_ENV=staging\n"],
            'key first' => ["APP_KEY=base64:abc\nDB_PASSWORD=secret\n"],
        ];
    }

    #[DataProvider('envLikeBodies')]
    public function test_recognises_env_file_contents(string $body): void
    {
        $this->assertTrue(EnvFileExposureCheck::bodyLooksLikeEnvFile($body));
    }

    public static function otherBodies(): array
    {
        return [
            'empty' => [''],
            'html page' => ['<!doctype html><html><body>Welcome</body></html>'],
            'spa with asset' => ['<html><head><script src="/build/app.js"></script></head></html>'],
            'key only' => ["APP_KEY=base64:abc\n"],
            'inline mention' => ['Here is a sample: APP_KEY=base64:abc and APP_ENV=local'],
            'login page' => ['<form><input name="password"></form>'],
        ];
    }

    #[DataProvider('otherBodies')]
    public function test_ignores_non_env_responses(string $body): void
    {
        $this->assertFalse(EnvFileExposureCheck::bodyLooksLikeEnvFile($body));
    }

    public function test_all_security_headers_present(): void
    {
        $headers = [
            'X-Frame-Options' => ['DENY'],
            'X-Content-Type-Options' => ['nosniff'],
            'Content-Security-Policy' => ["default-src 'self'"],
            'Strict-Transport-Security' => ['max-age=31536000'],
        ];

        $this->assertSame([], SecurityHeadersCheck::missingHeaders($headers, self::REQUIRED_HEADERS, true));
    }

    public function test_csp_frame_ancestors_replaces_frame_options(): void
    {
        $headers = [
            'content-security-policy' => ["default-src 'self'; frame-ancestors 'none'"],
            'x-content-type-options' => ['nosniff'],
            'strict-transport-security' => ['max-age=31536000'],
        ];

        $this->assertSame([], SecurityHeadersCheck::missingHeaders($headers, self::REQUIRED_HEADERS, true));
    }

    public function test_reports_missing_headers(): void
    {
        $this->assertSame([
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'Strict-Transport-Security',
        ], SecurityHeadersCheck::missingHeaders(['server' => ['nginx']], self::REQUIRED_HEADERS, true));
    }

    public function test_hsts_is_only_required_for_https(): void
    {
        $headers = [
            'x-frame-options' => ['DENY'],
            'x-content-type-options' => ['nosniff'],
            'content-security-policy' => ["default-src 'self'"],
        ];

        $this->assertSame([], SecurityHeadersCheck::missingHeaders($headers, self::REQUIRED_HEADERS, false));
    }

    public function test_ssl_verdict_warns_three_days_before_expiry(): void
    {
        $this->assertSame(Result::WARN, SslCertificateCheck::verdict(3, 3));
        $this->assertSame(Result::WARN, SslCertificateCheck::verdict(1, 3));
        $this->assertSame(Result::PASS, SslCertificateCheck::verdict(4, 3));
        $this->assertSame(Result::FAIL, SslCertificateCheck::verdict(-1, 3));
    }

    public function test_ssl_days_until_handles_expired_certificates(): void
    {
        $now = 1_700_000_000;

        $this->assertSame(3, SslCertificateCheck::daysUntil($now + (3 * 86400), $now));
        $this->assertSame(0, SslCertificateCheck::daysUntil($now + 3600, $now));
        $this->assertSame(-1, SslCertificateCheck::daysUntil($now - 86400, $now));
    }

    public function test_recognises_real_public_domains(): void
    {
        $this->assertTrue(DomainEnvironmentCheck::isRealDomain('example.com'));
        $this->assertTrue(DomainEnvironmentCheck::isRealDomain('www.example.com'));
        $this->assertTrue(DomainEnvironmentCheck::isRealDomain('sub.domain.co.uk'));
        $this->assertTrue(DomainEnvironmentCheck::isRealDomain('EXAMPLE.COM'));
    }

    public function test_rejects_non_public_hosts(): void
    {
        foreach ([
            '',
            'localhost',
            'g2-new.test',
            'app.local',
            'shop.example',
            'site.invalid',
            'anything.internal',
            '127.0.0.1',
            '10.0.0.5',
            '192.168.1.20',
            '[::1]',
            'no-tld',
            'bad_domain.com',
        ] as $host) {
            $this->assertFalse(DomainEnvironmentCheck::isRealDomain($host), "{$host} should not be a real domain");
        }
    }

    public function test_report_summarises_and_fingerprints_results(): void
    {
        $report = new Report([
            Result::pass('app_key', 'App key', 'set'),
            Result::warn('https', 'HTTPS', 'not https'),
            Result::fail('env_exposure', '.env exposure', 'https://example.test/.env'),
        ], 'https://example.test');

        $this->assertTrue($report->hasFailures());
        $this->assertSame(['env_exposure'], $report->failureKeys());
        $this->assertSame(['pass' => 1, 'warn' => 1, 'fail' => 1, 'total' => 3], $report->summary());
        $this->assertSame($report->fingerprint(), (new Report(array_reverse($report->results)))->fingerprint());
    }
}