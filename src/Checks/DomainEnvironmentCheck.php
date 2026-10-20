<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;

/**
 * Warns when APP_URL points at a real public domain but the application is not
 * running with the production environment (and vice versa). A common cause of
 * "why is debug on for customers?" incidents.
 */
class DomainEnvironmentCheck extends Check
{
    /**
     * TLDs and names that can never be a real public domain.
     *
     * @var array<int, string>
     */
    private const RESERVED_TLDS = [
        'localhost',
        'local',
        'test',
        'example',
        'invalid',
        'internal',
        'lan',
        'home',
        'corp',
        'intranet',
        'onion',
    ];

    public function key(): string
    {
        return 'domain';
    }

    public function label(): string
    {
        return 'Domain / environment';
    }

    public function run(): Result
    {
        $url = (string) config('app.url');

        if ($url === '') {
            return $this->fail('APP_URL is not set.');
        }

        $host = (string) parse_url($url, PHP_URL_HOST);

        if ($host === '') {
            return $this->warn("Could not parse a host from APP_URL ({$url}).");
        }

        $environment = app()->environment();
        $production = $this->isProduction();
        $realDomain = self::isRealDomain($host);

        if ($realDomain && ! $production) {
            return $this->warn("APP_URL points at the public domain {$host} but APP_ENV is \"{$environment}\" - make sure production is not served with dev/staging settings.");
        }

        if (! $realDomain && $production) {
            return $this->warn("APP_ENV is production but APP_URL points at {$host}, which is not a public domain.");
        }

        if ($realDomain) {
            return $this->pass("{$host} is a public domain and APP_ENV is production.");
        }

        return $this->pass("{$host} is a local/test domain ({$environment} environment).");
    }

    /**
     * True when the host looks like a routable public domain (not localhost,
     * an IP address, or one of the reserved/special-use names).
     */
    public static function isRealDomain(string $host): bool
    {
        $host = strtolower(trim($host));

        if ($host === '') {
            return false;
        }

        // parse_url() keeps the brackets around IPv6 literals.
        $bare = trim($host, '[]');

        if (filter_var($bare, FILTER_VALIDATE_IP) !== false) {
            return false;
        }

        if (! str_contains($host, '.')) {
            return false;
        }

        $tld = substr($host, (int) strrpos($host, '.') + 1);

        if (in_array($tld, self::RESERVED_TLDS, true)) {
            return false;
        }

        return preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $host) === 1;
    }
}