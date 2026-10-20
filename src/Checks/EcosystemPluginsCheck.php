<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;

class EcosystemPluginsCheck extends Check
{
    public function key(): string
    {
        return 'plugins';
    }

    public function label(): string
    {
        return 'Ecosystem plugins';
    }

    public function run(): Result
    {
        $packages = (array) config('sanity-check.checks.plugins.packages', []);
        $installed = [];
        $shouldBeOff = [];
        $shouldBeOn = [];

        foreach ($packages as $name => $package) {
            $class = $package['class'] ?? null;

            if ($class === null || ! class_exists($class)) {
                continue;
            }

            $configKey = $package['config'] ?? null;
            $enabled = $configKey === null ? null : (bool) config($configKey, false);
            $expect = $package['expect'] ?? 'ignore';

            $state = match (true) {
                $enabled === null => 'installed',
                $enabled => 'enabled',
                default => 'disabled',
            };

            $installed[] = "{$name} ({$state})";

            if (! $this->isProduction() || $expect === 'ignore' || $enabled === null) {
                continue;
            }

            if ($expect === 'disabled' && $enabled) {
                $shouldBeOff[] = $name;
            }

            if ($expect === 'enabled' && ! $enabled) {
                $shouldBeOn[] = $name;
            }
        }

        if ($installed === []) {
            return $this->pass('No Laravel ecosystem plugin is installed.');
        }

        $summary = 'Installed: ' . implode(', ', $installed);

        if ($shouldBeOff !== []) {
            return $this->fail($summary . '. Enabled in production but should be off or gated: ' . implode(', ', $shouldBeOff) . '.');
        }

        if ($shouldBeOn !== []) {
            return $this->warn($summary . '. Expected to run in production but disabled: ' . implode(', ', $shouldBeOn) . '.');
        }

        return $this->pass($summary . '.');
    }
}