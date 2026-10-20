<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Studio\Totem\Totem;
use Throwable;

class TotemCheck extends Check
{
    public function key(): string
    {
        return 'totem';
    }

    public function label(): string
    {
        return 'Totem';
    }

    public function run(): Result
    {
        if (! class_exists(Totem::class)) {
            return $this->warn('Totem is not installed.');
        }

        try {
            if (! Totem::isEnabled()) {
                return $this->fail('Totem is not enabled - the tasks table is missing.');
            }

            $active = app('totem.tasks')->findAllActive();
        } catch (Throwable $e) {
            return $this->warn('Unable to read tasks: ' . $e->getMessage());
        }

        $activeCount = $active->count();

        if ($activeCount === 0) {
            return $this->warn('Totem is enabled but has no active tasks.');
        }

        $details = "{$activeCount} active task(s)";
        $registered = $this->registeredTaskCount($active->pluck('description')->filter()->all());

        if ($registered !== null) {
            $details .= ", {$registered} registered in the scheduler";
        }

        $lastRun = $this->lastRun();

        if ($lastRun === null) {
            return $this->warn("{$details}, but no task has produced a result yet.");
        }

        $details .= ', last result ' . $lastRun->diffForHumans();

        $maxAge = (int) config('sanity-check.checks.totem.max_result_age_hours', 24);

        if ($lastRun->lt(now()->subHours($maxAge))) {
            return $this->warn("{$details} - is the scheduler cron running?");
        }

        return $this->pass("{$details}.");
    }

    /**
     * @param  array<int, string>  $descriptions
     */
    private function registeredTaskCount(array $descriptions): ?int
    {
        if ($descriptions === []) {
            return null;
        }

        try {
            $events = app(\Illuminate\Console\Scheduling\Schedule::class)->events();
        } catch (Throwable $e) {
            return null;
        }

        return collect($events)
            ->filter(fn ($event) => in_array($event->description, $descriptions, true))
            ->count();
    }

    private function lastRun(): ?Carbon
    {
        $table = config('totem.table_prefix', '') . 'task_results';

        try {
            if (! Schema::hasTable($table)) {
                return null;
            }

            $lastRun = DB::connection(config('totem.database_connection'))->table($table)->max('ran_at');
        } catch (Throwable $e) {
            return null;
        }

        return $lastRun ? Carbon::parse($lastRun) : null;
    }
}