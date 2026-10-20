<?php

namespace BluedotBd\SanityCheck\Notifications\Channels;

use BluedotBd\SanityCheck\Notifications\Mail\ReportMail;
use BluedotBd\SanityCheck\Report;
use Illuminate\Support\Facades\Mail;
use RuntimeException;

class MailChannel implements Channel
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(private array $config)
    {
    }

    public function name(): string
    {
        return 'mail';
    }

    public function send(Report $report): void
    {
        $to = array_values(array_filter((array) ($this->config['to'] ?? [])));

        if ($to === []) {
            throw new RuntimeException('No mail recipients configured (sanity-check.notifications.channels.mail.to).');
        }

        Mail::to($to)->send(new ReportMail($report, (string) ($this->config['subject'] ?? 'SanityCheck security report')));
    }
}