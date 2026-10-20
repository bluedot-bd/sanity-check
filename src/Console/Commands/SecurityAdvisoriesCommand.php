<?php

namespace BluedotBd\SanityCheck\Console\Commands;

use BluedotBd\SanityCheck\Notifications\Notifier;
use BluedotBd\SanityCheck\Report;
use BluedotBd\SanityCheck\Results\Result;
use BluedotBd\SanityCheck\Support\AdvisoryClient;
use BluedotBd\SanityCheck\Support\InstalledPackages;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class SecurityAdvisoriesCommand extends Command
{
    protected $signature = 'sanity-check:advisories
        {--json : Print the findings as JSON}
        {--ignore= : Comma separated advisory ids to ignore}
        {--no-notify : Do not send notifications}';

    protected $description = 'Check installed packages against the Packagist security advisories API';

    public function handle(AdvisoryClient $client, Notifier $notifier): int
    {
        $packages = InstalledPackages::read((bool) config('sanity-check.advisories.include_dev', true));

        if ($packages === []) {
            $this->components->warn('No installed packages found - run "composer install" first.');

            return self::FAILURE;
        }

        $ignore = array_values(array_unique(array_merge(
            (array) config('sanity-check.advisories.ignore', []),
            $this->parseList((string) $this->option('ignore'))
        )));

        $result = $client->find($packages, $ignore);
        $report = $this->buildReport($result['findings'], $result['errors'], count($packages));

        $this->render($result['findings'], $result['errors'], count($packages));
        $this->log($result['findings'], $report);

        if (! $this->option('no-notify')) {
            foreach ($notifier->send($report) as $channel => $outcome) {
                $this->components->twoColumnDetail(
                    'Notify: ' . $channel,
                    $outcome === 'sent' ? '<fg=green>sent</>' : '<fg=yellow>' . $outcome . '</>'
                );
            }
        }

        return $result['findings'] === [] ? self::SUCCESS : self::FAILURE;
    }

    /**
     * @param  array<int, array<string, string>>  $findings
     * @param  array<int, string>  $errors
     */
    private function buildReport(array $findings, array $errors, int $checked): Report
    {
        $results = [];

        foreach ($findings as $finding) {
            $results[] = Result::fail(
                'advisories.' . $finding['package'],
                $finding['package'] . ' ' . $finding['version'],
                trim(sprintf(
                    '%s: %s%s',
                    $finding['advisory_id'] ?: ($finding['cve'] ?: 'advisory'),
                    $finding['title'],
                    $finding['link'] !== '' ? ' (' . $finding['link'] . ')' : ''
                ))
            );
        }

        foreach ($errors as $error) {
            $results[] = Result::warn('advisories.lookup', 'Advisory lookup', $error);
        }

        if ($findings === [] && $errors === []) {
            $results[] = Result::pass('advisories', 'Security advisories', "No advisory affects the {$checked} installed packages.");
        }

        return new Report($results, (string) config('app.url'));
    }

    /**
     * @param  array<int, array<string, string>>  $findings
     * @param  array<int, string>  $errors
     */
    private function render(array $findings, array $errors, int $checked): void
    {
        if ($this->option('json')) {
            $this->line((string) json_encode([
                'checked' => $checked,
                'findings' => $findings,
                'errors' => $errors,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return;
        }

        if ($findings === []) {
            $this->components->info("No advisory affects the {$checked} installed packages.");

            return;
        }

        $this->table(
            ['Package', 'Installed', 'Advisory', 'Affected versions', 'Title'],
            array_map(fn (array $finding) => [
                $finding['package'],
                $finding['version'],
                $finding['advisory_id'] ?: $finding['cve'],
                $finding['affected'],
                $finding['title'],
            ], $findings)
        );

        $this->components->error(count($findings) . ' security advisory(ies) affect installed packages.');

        foreach ($errors as $error) {
            $this->components->warn($error);
        }
    }

    /**
     * @param  array<int, array<string, string>>  $findings
     */
    private function log(array $findings, Report $report): void
    {
        if ($findings === []) {
            return;
        }

        try {
            $shouldLog = Cache::add('sanity-check:advisories:log:' . $report->fingerprint(), true, 3600);
        } catch (\Throwable $e) {
            $shouldLog = true;
        }

        if ($shouldLog) {
            Log::critical('SanityCheck found security advisories affecting installed packages', [
                'findings' => $findings,
            ]);
        }
    }

    /**
     * @return array<int, string>
     */
    private function parseList(string $value): array
    {
        if (trim($value) === '') {
            return [];
        }

        return array_values(array_filter(array_map('trim', explode(',', $value))));
    }
}