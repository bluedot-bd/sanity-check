<?php

namespace BluedotBd\SanityCheck\Support;

/**
 * Reads the npm packages that are installed so they can be sent to the npm
 * advisory endpoint (package-lock.json first, package.json as a fallback).
 */
class NodePackages
{
    /**
     * @return array{packages: array<string, string>, source: string}|null
     */
    public static function read(?string $packageJson = null, bool $includeDev = true): ?array
    {
        $packageJson = $packageJson ?: base_path('package.json');

        if (! is_file($packageJson)) {
            return null;
        }

        $directory = dirname($packageJson);

        foreach (['package-lock.json', 'npm-shrinkwrap.json'] as $lockFile) {
            $path = $directory . DIRECTORY_SEPARATOR . $lockFile;

            if (! is_file($path)) {
                continue;
            }

            $packages = self::fromLockJson((string) file_get_contents($path), $includeDev);

            if ($packages !== []) {
                return ['packages' => $packages, 'source' => $lockFile];
            }
        }

        return [
            'packages' => self::fromPackageJson((string) file_get_contents($packageJson), $includeDev),
            'source' => 'package.json (version ranges, approximate)',
        ];
    }

    /**
     * @return array<string, string> package name => version
     */
    public static function fromPackageJson(string $json, bool $includeDev = true): array
    {
        $data = json_decode($json, true);

        if (! is_array($data)) {
            return [];
        }

        $specs = (array) ($data['dependencies'] ?? []);

        if ($includeDev) {
            $specs += (array) ($data['devDependencies'] ?? []);
        }

        $specs += (array) ($data['optionalDependencies'] ?? []);

        $packages = [];

        foreach ($specs as $name => $spec) {
            $version = self::lowestVersion((string) $spec);

            if ($version !== null) {
                $packages[(string) $name] = $version;
            }
        }

        ksort($packages);

        return $packages;
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

        // lockfileVersion 2 and 3: a flat "packages" map keyed by node_modules path.
        if (isset($data['packages']) && is_array($data['packages'])) {
            $installed = [];

            foreach ($data['packages'] as $path => $meta) {
                $path = (string) $path;

                if ($path === '' || ! is_array($meta) || empty($meta['version'])) {
                    continue;
                }

                if (! $includeDev && ! empty($meta['dev'])) {
                    continue;
                }

                $name = self::nameFromPath($path, (string) ($meta['name'] ?? ''));

                if ($name !== '') {
                    $installed[$name] = (string) $meta['version'];
                }
            }

            ksort($installed);

            return $installed;
        }

        // lockfileVersion 1: nested dependency tree.
        $installed = [];
        self::collectTree((array) ($data['dependencies'] ?? []), $installed, $includeDev);
        ksort($installed);

        return $installed;
    }

    /**
     * Turn a package.json range (^1.2.3, ~1.2, >=1.0.0 <2) into a concrete
     * version. Non registry specs (git:, file:, workspace:, latest) are skipped.
     */
    public static function lowestVersion(string $spec): ?string
    {
        $spec = trim($spec);

        if ($spec === '' || preg_match('/[a-z]+:/i', $spec) === 1) {
            return null;
        }

        if (preg_match('/\d+(?:\.\d+){0,2}/', $spec, $matches) !== 1) {
            return null;
        }

        return implode('.', array_slice(array_pad(explode('.', $matches[0]), 3, '0'), 0, 3));
    }

    private static function nameFromPath(string $path, string $fallback): string
    {
        $marker = 'node_modules/';
        $position = strrpos($path, $marker);

        if ($position === false) {
            return $fallback;
        }

        return substr($path, $position + strlen($marker));
    }

    /**
     * @param  array<string, mixed>  $dependencies
     * @param  array<string, string>  $installed
     */
    private static function collectTree(array $dependencies, array &$installed, bool $includeDev): void
    {
        foreach ($dependencies as $name => $meta) {
            if (! is_array($meta)) {
                continue;
            }

            if (! $includeDev && ! empty($meta['dev'])) {
                continue;
            }

            if (! empty($meta['version'])) {
                $installed[(string) $name] = (string) $meta['version'];
            }

            if (! empty($meta['dependencies']) && is_array($meta['dependencies'])) {
                self::collectTree($meta['dependencies'], $installed, $includeDev);
            }
        }
    }
}