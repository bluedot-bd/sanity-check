<?php

namespace BluedotBd\SanityCheck\Notifications\Channels;

use BluedotBd\SanityCheck\Report;
use BluedotBd\SanityCheck\Results\Result;
use Illuminate\Support\Facades\Http;
use RuntimeException;

class SlackChannel implements Channel
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(private array $config)
    {
    }

    public function name(): string
    {
        return 'slack';
    }

    public function send(Report $report): void
    {
        $url = (string) ($this->config['webhook_url'] ?? '');

        if ($url === '') {
            throw new RuntimeException('No Slack webhook configured (SANITY_CHECK_SLACK_WEBHOOK).');
        }

        $attachments = array_values(array_filter([
            $this->attachment('Failed checks', $report->failures(), 'danger'),
            $this->attachment('Warnings', $report->warnings(), 'warning'),
            $this->heartbeatAttachment($report),
        ]));

        $payload = [
            'text' => $this->headline($report),
            'attachments' => $attachments,
        ];

        if (! empty($this->config['channel'])) {
            $payload['channel'] = (string) $this->config['channel'];
        }

        Http::timeout((int) ($this->config['timeout'] ?? 5))->post($url, $payload)->throw();
    }

    private function headline(Report $report): string
    {
        if ($report->heartbeat) {
            return sprintf(
                '*SanityCheck* on %s (%s): daily check ran clean - no issues detected. SanityCheck is alive.',
                (string) config('app.name'),
                app()->environment()
            );
        }

        $summary = $report->summary();

        return sprintf(
            '*SanityCheck* on %s (%s): %d failed, %d warnings',
            (string) config('app.name'),
            app()->environment(),
            $summary['fail'],
            $summary['warn']
        );
    }

    /**
     * @return array<string, mixed>|null
     */
    private function heartbeatAttachment(Report $report): ?array
    {
        if (! $report->heartbeat || ! $report->isClean()) {
            return null;
        }

        $lines = array_map(fn (Result $result) => '• *' . $result->label . '* — ' . $result->detail, $report->results);

        return [
            'color' => 'good',
            'title' => 'All clear',
            'text' => implode("\n", $lines) ?: 'No findings.',
            'mrkdwn_in' => ['text'],
        ];
    }

    /**
     * @param  array<int, Result>  $results
     * @return array<string, mixed>|null
     */
    private function attachment(string $title, array $results, string $color): ?array
    {
        if ($results === []) {
            return null;
        }

        $lines = array_map(fn (Result $result) => '• *' . $result->label . '* — ' . $result->detail, $results);

        return [
            'color' => $color,
            'title' => $title,
            'text' => implode("\n", $lines),
            'mrkdwn_in' => ['text'],
        ];
    }
}