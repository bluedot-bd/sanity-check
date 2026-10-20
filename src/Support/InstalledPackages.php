<?php

namespace BluedotBd\SanityCheck\Support;

/**
 * Reads the packages that are actually installed so they can be sent to the
 * Packagist security advisories API.
 */
class InstalledPackages
{
    /**
     * @return array<string, string> package name => normalized version
     */
    public static function read(bool $includeDev = true): array
    {
        foreach ([['vendor/composer/installed.json', 'fromInstalledJson'], ['composer.lock', 'fromLockJson']] as [$file, $parser]) {
            $path = base_path($file);

            if (! is_file($path)) {
                continue;
            }

            $contents = @file_get_contents($path);

            if (is_string($contents) && $contents !== '') {
                return self::$parser($contents, $includeDev);
            }
        }

        return [];
    }

    /**
     * @return array<string, string>
     */
    public static function fromInstalledJson(string $json, bool $includeDev = true): array
    {
        $data = json_decode($json, true);

        if (! is_array($data)) {
            return [];
        }

        $packages = $data['packages'] ?? $data;

        if (isset($data['packages-dev'])) {
            $packages = array_merge((array) $packages, (array) $data['packages-dev']);
        }

        return self::collect((array) $packages, $includeDev);
    }

    /**
     * @return array<string, string>
     */
    public static function fromLockJson(string $json, bool $includeDev = true): array
    {
        $data = json_decode($json, true);

        if (! is_array($data)) {
            return [];
        }

        $packages = (array) ($data['packages'] ?? []);

        if ($includeDev) {
            $packages = array_merge($packages, (array) ($data['packages-dev'] ?? []));
        }

        return self::collect($packages, $includeDev);
    }

    /**
     * @param  array<int, mixed>  $packages
     * @return array<string, string>
     */
    private static function collect(array $packages, bool $includeDev): array
    {
        $installed = [];

        foreach ($packages as $package) {
            if (! is_array($package) || empty($package['name'])) {
                continue;
            }

            if (! $includeDev && ($package['dev_requirement'] ?? false)) {
                continue;
            }

            $installed[(string) $package['name']] = (string) ($package['version_normalized'] ?? $package['version'] ?? '');
        }

        ksort($installed);

        return $installed;
    }
}