<?php

namespace BluedotBd\SanityCheck\Console\Commands;

use BluedotBd\SanityCheck\Actions\MaintenanceAction;
use BluedotBd\SanityCheck\Notifications\Notifier;
use BluedotBd\SanityCheck\Report;
use BluedotBd\SanityCheck\Results\Result;
use BluedotBd\SanityCheck\SanityCheck;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class SanityCheckCommand extends Command
{
    protected $signature = 'sanity-check:run
        {--url= : Base URL for remote probes (defaults to sanity-check.probe.url or app.url)}
        {--only= : Comma separated check keys to run}
        {--skip-remote : Skip the HTTP probes}
        {--dry-run : Report findings without changing maintenance mode}
        {--no-notify : Do not send notifications}
        {--json : Print the report as JSON}';

    protected $description = 'Run security posture checks, send alerts and apply the configured actions';

    public function __construct()
    {
        parent::__construct();

        $this->setAliases(['security:check']);
    }

    public function handle(SanityCheck $sanity, MaintenanceAction $maintenance, Notifier $notifier): int
    {
        $report = $sanity->run(
            $this->option('url') ?: null,
            $this->only(),
            (bool) $this->option('skip-remote')
        );

        $this->render($report);
        $this->logFailures($report);
        $this->applyMaintenance($report, $maintenance);
        $this->notify($report, $notifier);

        return $report->hasFailures() ? self::FAILURE : self::SUCCESS;
    }

    private function render(Report $report): void
    {
        if ($this->option('json')) {
            $this->line((string) json_encode($report->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return;
        }

        $rows = array_map(fn (Result $result) => [
            $result->label,
            match ($result->status) {
                Result::PASS => '<fg=green>PASS</>',
                Result::WARN => '<fg=yellow>WARN</>',
                default => '<fg=red>FAIL</>',
            },
            $result->detail,
        ], $report->results);

        $this->newLine();
        $this->table(['Check', 'Status', 'Details'], $rows);

        $summary = $report->summary();

        $this->components->info("{$summary['pass']} passed, {$summary['warn']} warning(s), {$summary['fail']} failed.");
    }

    private function logFailures(Report $report): void
    {
        if (! $report->hasFailures()) {
            return;
        }

        try {
            $shouldLog = Cache::add('sanity-check:log:' . $report->fingerprint(), true, 3600);
        } catch (\Throwable $e) {
            $shouldLog = true;
        }

        if (! $shouldLog) {
            return;
        }

        Log::critical('SanityCheck found failing security checks', [
            'url' => $report->url,
            'failures' => array_map(fn (Result $result) => $result->toArray(), $report->failures()),
        ]);
    }

    private function applyMaintenance(Report $report, MaintenanceAction $maintenance): void
    {
        $triggered = $maintenance->triggeredBy($report);

        if ($triggered === []) {
            return;
        }

        if ($this->option('dry-run')) {
            $this->components->warn('Maintenance mode NOT enabled (--dry-run): ' . implode(', ', $triggered));

            return;
        }

        if ($maintenance->isAlreadyDown()) {
            $this->components->info('Application is already down for maintenance.');

            return;
        }

        if ($maintenance->enable($triggered)) {
            $this->components->error('Application put into maintenance mode (' . implode(', ', $triggered) . ' failed).');

            return;
        }

        $this->components->error('Could not enable maintenance mode - run "php artisan down" manually.');
    }

    private function notify(Report $report, Notifier $notifier): void
    {
        if ($this->option('no-notify')) {
            return;
        }

        foreach ($notifier->send($report) as $channel => $outcome) {
            $this->components->twoColumnDetail(
                'Notify: ' . $channel,
                $outcome === 'sent' ? '<fg=green>sent</>' : '<fg=yellow>' . $outcome . '</>'
            );
        }
    }

    /**
     * @return array<int, string>|null
     */
    private function only(): ?array
    {
        $only = trim((string) $this->option('only'));

        if ($only === '') {
            return null;
        }

        return array_values(array_filter(array_map('trim', explode(',', $only))));
    }
}