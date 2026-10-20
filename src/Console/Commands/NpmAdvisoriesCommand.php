<?php

namespace BluedotBd\SanityCheck\Console\Commands;

use BluedotBd\SanityCheck\Notifications\Notifier;
use BluedotBd\SanityCheck\Report;
use BluedotBd\SanityCheck\Results\Result;
use BluedotBd\SanityCheck\Support\NodePackages;
use BluedotBd\SanityCheck\Support\NpmAdvisoryClient;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class NpmAdvisoriesCommand extends Command
{
    protected $signature = 'sanity-check:npm-advisories
        {--path= : Path to package.json (defaults to the application root)}
        {--json : Print the findings as JSON}
        {--ignore= : Comma separated advisory ids to ignore}
        {--no-notify : Do not send notifications}';

    protected $description = 'Check package.json / package-lock.json against the npm security advisories API';

    public function handle(NpmAdvisoryClient $client, Notifier $notifier): int
    {
        $config = (array) config('sanity-check.npm_advisories', []);
        $path = (string) ($this->option('path') ?: ($config['path'] ?? '') ?: base_path('package.json'));
        $includeDev = (bool) ($config['include_dev'] ?? true);

        $node = NodePackages::read($path, $includeDev);

        if ($node === null) {
            $this->components->warn("No package.json found at {$path}.");

            return self::SUCCESS;
        }

        $packages = $node['packages'];

        if ($packages === []) {
            $this->components->warn("{$path} does not declare any versioned dependency.");

            return self::SUCCESS;
        }

        $ignore = array_values(array_unique(array_merge(
            (array) ($config['ignore'] ?? []),
            $this->parseList((string) $this->option('ignore'))
        )));

        $result = $client->find($packages, $ignore, (array) ($config['severities'] ?? []));
        $report = $this->buildReport($result['findings'], $result['errors'], count($packages));

        $this->render($result['findings'], $result['errors'], count($packages), $node['source']);
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
                'npm_advisories.' . $finding['package'],
                $finding['package'] . ' ' . $finding['version'],
                trim(sprintf(
                    '%s %s: %s%s',
                    strtoupper($finding['severity']),
                    $finding['advisory_id'] !== '' ? '#' . $finding['advisory_id'] : '',
                    $finding['title'],
                    $finding['url'] !== '' ? ' (' . $finding['url'] . ')' : ''
                ))
            );
        }

        foreach ($errors as $error) {
            $results[] = Result::warn('npm_advisories.lookup', 'npm advisory lookup', $error);
        }

        if ($findings === [] && $errors === []) {
            $results[] = Result::pass('npm_advisories', 'npm advisories', "No advisory affects the {$checked} installed npm packages.");
        }

        return new Report($results, (string) config('app.url'));
    }

    /**
     * @param  array<int, array<string, string>>  $findings
     * @param  array<int, string>  $errors
     */
    private function render(array $findings, array $errors, int $checked, string $source): void
    {
        if ($this->option('json')) {
            $this->line((string) json_encode([
                'source' => $source,
                'checked' => $checked,
                'findings' => $findings,
                'errors' => $errors,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return;
        }

        if ($findings === []) {
            $this->components->info("No advisory affects the {$checked} npm packages read from {$source}.");

            foreach ($errors as $error) {
                $this->components->warn($error);
            }

            return;
        }

        $this->table(
            ['Package', 'Installed', 'Severity', 'Advisory', 'Vulnerable', 'Title'],
            array_map(fn (array $finding) => [
                $finding['package'],
                $finding['version'],
                strtoupper($finding['severity']),
                $finding['advisory_id'],
                $finding['vulnerable'],
                $finding['title'],
            ], $findings)
        );

        $this->components->error(count($findings) . ' npm advisory(ies) affect installed packages.');

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
            $shouldLog = Cache::add('sanity-check:npm-advisories:log:' . $report->fingerprint(), true, 3600);
        } catch (\Throwable $e) {
            $shouldLog = true;
        }

        if ($shouldLog) {
            Log::critical('SanityCheck found npm advisories affecting installed packages', [
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