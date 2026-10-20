<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;

class HttpsCheck extends Check
{
    public function key(): string
    {
        return 'https';
    }

    public function label(): string
    {
        return 'HTTPS / APP_URL';
    }

    public function run(): Result
    {
        $url = (string) config('app.url');

        if ($url === '') {
            return $this->fail('APP_URL is not set.');
        }

        if (str_starts_with($url, 'https://')) {
            return $this->pass("APP_URL uses HTTPS ({$url}).");
        }

        return $this->productionIssue("APP_URL is not HTTPS ({$url}).");
    }
}