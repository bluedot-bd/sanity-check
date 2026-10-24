<?php

namespace BluedotBd\SanityCheck\Notifications\Mail;

use BluedotBd\SanityCheck\Report;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class ReportMail extends Mailable
{
    use Queueable;
    use SerializesModels;

    public function __construct(public Report $report, public string $reportSubject = 'SanityCheck security report')
    {
    }

    public function build(): self
    {
        $summary = $this->report->summary();

        $subject = $this->report->heartbeat
            ? sprintf('%s - all clear', $this->reportSubject)
            : sprintf('%s - %d failed, %d warnings', $this->reportSubject, $summary['fail'], $summary['warn']);

        return $this
            ->subject($subject)
            ->view('sanity-check::mail.report', ['report' => $this->report]);
    }
}