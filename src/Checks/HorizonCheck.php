<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;
use Laravel\Horizon\Contracts\MasterSupervisorRepository;
use Throwable;

class HorizonCheck extends Check
{
    public function key(): string
    {
        return 'horizon';
    }

    public function label(): string
    {
        return 'Horizon';
    }

    public function run(): Result
    {
        if (! interface_exists(MasterSupervisorRepository::class)) {
            return $this->warn('Horizon is not installed.');
        }

        try {
            $masters = app(MasterSupervisorRepository::class)->all();
        } catch (Throwable $e) {
            return $this->warn('Unable to read supervisors: ' . $e->getMessage());
        }

        if (empty($masters)) {
            return $this->fail('No master supervisor found - Horizon is not running.');
        }

        $names = collect($masters)->pluck('name')->implode(', ');
        $paused = collect($masters)->filter(fn ($master) => ($master->status ?? null) === 'paused')->count();
        $running = count($masters) - $paused;

        if ($running === 0) {
            return $this->warn("All supervisors are paused ({$names}).");
        }

        return $this->pass("{$running} supervisor(s) running, {$paused} paused ({$names}).");
    }
}