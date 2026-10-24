<?php

namespace BluedotBd\SanityCheck\Support;

/**
 * Resolves the URL a dashboard is actually served from.
 *
 * Horizon and Totem can each be mounted on their own host and URI, configured
 * by whoever deploys them (horizon.domain / horizon.path, totem.allowed_hosts /
 * totem.web.route_prefix). Probing APP_URL instead reaches the wrong vhost and
 * gets a 404, which the exposure checks would then report as "protected" - a
 * false pass on the most dangerous dashboard in the app.
 */
final class DashboardUrl
{
    public static function build(?string $baseUrl, string $path, array|string|null $domain = null): ?string
    {
        $path = trim($path, '/');
        $host = self::host($domain);

        if ($host !== null) {
            $scheme = parse_url((string) $baseUrl, PHP_URL_SCHEME) ?: 'https';

            return $scheme . '://' . $host . '/' . $path;
        }

        if ($baseUrl === null || trim($baseUrl) === '') {
            return null;
        }

        return rtrim($baseUrl, '/') . '/' . $path;
    }

    /**
     * Reduce a configured host to "host" or "host:port".
     *
     * Accepts "admincore.pro", "https://admincore.pro/", "admincore.pro:8443"
     * and comma-separated lists, because ADMIN_DOMAIN and TOTEM_ALLOWED_HOSTS
     * are written both ways. The first usable entry wins - it is the canonical
     * host the dashboard redirects to.
     */
    public static function host(array|string|null $configured): ?string
    {
        $values = is_array($configured) ? $configured : explode(',', (string) $configured);

        foreach ($values as $value) {
            $value = trim((string) $value);

            if ($value === '') {
                continue;
            }

            if (! str_contains($value, '://')) {
                $value = 'https://' . $value;
            }

            $host = parse_url($value, PHP_URL_HOST);

            if (! is_string($host) || $host === '') {
                continue;
            }

            $port = parse_url($value, PHP_URL_PORT);

            return strtolower($port === null ? $host : $host . ':' . $port);
        }

        return null;
    }
}
