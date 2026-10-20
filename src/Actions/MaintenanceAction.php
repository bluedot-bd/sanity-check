<?php

namespace BluedotBd\SanityCheck\Actions;

use BluedotBd\SanityCheck\Report;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\Artisan;
use Throwable;

class MaintenanceAction
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(private Container $app, private array $config = [])
    {
    }

    /**
     * Failing check keys that should put the application into maintenance mode.
     *
     * @return array<int, string>
     */
    public function triggeredBy(Report $report): array
    {
        if (! ($this->config['enabled'] ?? false)) {
            return [];
        }

        $trigger = (array) ($this->config['trigger_on'] ?? []);

        if (in_array('*', $trigger, true)) {
            return $report->failureKeys();
        }

        return array_values(array_intersect($report->failureKeys(), $trigger));
    }

    public function isAlreadyDown(): bool
    {
        try {
            if (method_exists($this->app, 'maintenanceMode')) {
                return $this->app->maintenanceMode()->active();
            }

            return $this->app->isDownForMaintenance();
        } catch (Throwable $e) {
            return false;
        }
    }

    /**
     * @param  array<int, string>  $triggered
     */
    public function enable(array $triggered): bool
    {
        if ($triggered === [] || $this->isAlreadyDown()) {
            return false;
        }

        $options = [];

        if (! empty($this->config['secret'])) {
            $options['--secret'] = (string) $this->config['secret'];
        }

        if (! empty($this->config['retry'])) {
            $options['--retry'] = (int) $this->config['retry'];
        }

        return Artisan::call('down', $options) === 0;
    }
}