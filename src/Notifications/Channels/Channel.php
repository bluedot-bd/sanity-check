<?php

namespace BluedotBd\SanityCheck\Notifications\Channels;

use BluedotBd\SanityCheck\Report;

interface Channel
{
    public function name(): string;

    public function send(Report $report): void;
}