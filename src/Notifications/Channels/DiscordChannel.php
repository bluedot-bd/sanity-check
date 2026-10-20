<?php

namespace BluedotBd\SanityCheck\Notifications\Channels;

use BluedotBd\SanityCheck\Report;
use BluedotBd\SanityCheck\Results\Result;
use Illuminate\Support\Facades\Http;
use RuntimeException;

class DiscordChannel implements Channel
{
    private const COLOR_FAILURE = 15158332;

    private const COLOR_WARNING = 16776960;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(private array $config)
    {
    }

    public function name(): string
    {
        return 'discord';
    }

    public function send(Report $report): void
    {
        $url = (string) ($this->config['webhook_url'] ?? '');

        if ($url === '') {
            throw new RuntimeException('No Discord webhook configured (SANITY_CHECK_DISCORD_WEBHOOK).');
        }

        $embeds = array_values(array_filter([
            $this->embed('Failed checks', $report->failures(), self::COLOR_FAILURE),
            $this->embed('Warnings', $report->warnings(), self::COLOR_WARNING),
        ]));

        Http::timeout((int) ($this->config['timeout'] ?? 5))->post($url, [
            'content' => $this->headline($report),
            'embeds' => $embeds,
        ])->throw();
    }

    private function headline(Report $report): string
    {
        $summary = $report->summary();

        return sprintf(
            'SanityCheck on %s (%s): %d failed, %d warnings',
            (string) config('app.name'),
            app()->environment(),
            $summary['fail'],
            $summary['warn']
        );
    }

    /**
     * @param  array<int, Result>  $results
     * @return array<string, mixed>|null
     */
    private function embed(string $title, array $results, int $color): ?array
    {
        if ($results === []) {
            return null;
        }

        $lines = array_map(fn (Result $result) => '**' . $result->label . '** — ' . $result->detail, $results);

        return [
            'title' => $title,
            'description' => implode("\n", $lines),
            'color' => $color,
        ];
    }
}