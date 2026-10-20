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

        return $this
            ->subject(sprintf('%s - %d failed, %d warnings', $this->reportSubject, $summary['fail'], $summary['warn']))
            ->view('sanity-check::mail.report', ['report' => $this->report]);
    }
}