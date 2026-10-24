<?php

namespace BluedotBd\SanityCheck\Notifications;

use BluedotBd\SanityCheck\Notifications\Channels\Channel;
use BluedotBd\SanityCheck\Notifications\Channels\DiscordChannel;
use BluedotBd\SanityCheck\Notifications\Channels\MailChannel;
use BluedotBd\SanityCheck\Notifications\Channels\SlackChannel;
use BluedotBd\SanityCheck\Notifications\Channels\WebhookChannel;
use BluedotBd\SanityCheck\Report;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use Throwable;

class Notifier
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(private Container $app, private array $config = [])
    {
    }

    /**
     * @return array<string, string> channel => outcome
     */
    public function send(Report $report): array
    {
        if (! ($this->config['enabled'] ?? false)) {
            return [];
        }

        $statuses = (array) ($this->config['statuses'] ?? ['fail']);

        $interesting = array_filter($report->results, fn ($result) => in_array($result->status, $statuses, true));

        if ($interesting === []) {
            return [];
        }

        return $this->dispatch($report);
    }

    /**
     * Announce a run that found nothing, so a silent schedule can be told
     * apart from a dead one. Never sent when the run has findings - a real
     * report always wins.
     *
     * @return array<string, string> channel => outcome
     */
    public function sendHeartbeat(Report $report): array
    {
        if (! $this->shouldSendHeartbeat($report)) {
            return [];
        }

        return $this->dispatch(new Report($report->results, $report->url, true));
    }

    public function shouldSendHeartbeat(Report $report): bool
    {
        return (bool) ($this->config['enabled'] ?? false)
            && (bool) ($this->config['heartbeat']['enabled'] ?? false)
            && $report->isClean();
    }

    /**
     * @return array<string, string> channel => outcome
     */
    private function dispatch(Report $report): array
    {
        $channels = $this->enabledChannels();

        if ($channels === []) {
            return [];
        }

        if ($this->throttled($report, array_keys($channels))) {
            return ['throttled' => 'An identical report was already sent recently.'];
        }

        $outcomes = [];

        foreach ($channels as $name => $config) {
            try {
                $this->make($name, $config)->send($report);
                $outcomes[$name] = 'sent';
            } catch (Throwable $e) {
                $outcomes[$name] = 'failed: ' . $e->getMessage();

                Log::error("SanityCheck notification via [{$name}] failed", ['exception' => $e->getMessage()]);
            }
        }

        return $outcomes;
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function enabledChannels(): array
    {
        return array_filter(
            (array) ($this->config['channels'] ?? []),
            fn ($config) => (bool) ($config['enabled'] ?? false)
        );
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private function make(string $name, array $config): Channel
    {
        return match ($name) {
            'mail' => new MailChannel($config),
            'webhook' => new WebhookChannel($config),
            'slack' => new SlackChannel($config),
            'discord' => new DiscordChannel($config),
            default => throw new InvalidArgumentException("Unknown SanityCheck notification channel [{$name}]."),
        };
    }

    /**
     * @param  array<int, string>  $channels
     */
    private function throttled(Report $report, array $channels): bool
    {
        $seconds = (int) ($this->config['throttle_seconds'] ?? 3600);

        if ($seconds <= 0) {
            return false;
        }

        $key = 'sanity-check:notify:' . md5($report->fingerprint() . '|' . implode(',', $channels));

        try {
            return ! Cache::add($key, true, $seconds);
        } catch (Throwable $e) {
            return false;
        }
    }
}