<?php

namespace BluedotBd\SanityCheck\Notifications\Channels;

use BluedotBd\SanityCheck\Report;
use BluedotBd\SanityCheck\Results\Result;
use Illuminate\Support\Facades\Http;
use RuntimeException;

class WebhookChannel implements Channel
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(private array $config)
    {
    }

    public function name(): string
    {
        return 'webhook';
    }

    public function send(Report $report): void
    {
        $url = (string) ($this->config['url'] ?? '');

        if ($url === '') {
            throw new RuntimeException('No webhook URL configured (SANITY_CHECK_WEBHOOK_URL).');
        }

        Http::withHeaders((array) ($this->config['headers'] ?? []))
            ->timeout((int) ($this->config['timeout'] ?? 5))
            ->post($url, [
                'source' => 'sanity-check',
                'app' => config('app.name'),
                'environment' => app()->environment(),
                'url' => $report->url,
                'checked_at' => now()->toIso8601String(),
                'summary' => $report->summary(),
                'failures' => array_map(fn (Result $result) => $result->toArray(), $report->failures()),
                'warnings' => array_map(fn (Result $result) => $result->toArray(), $report->warnings()),
            ])
            ->throw();
    }
}