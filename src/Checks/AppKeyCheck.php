<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;

class AppKeyCheck extends Check
{
    public function key(): string
    {
        return 'app_key';
    }

    public function label(): string
    {
        return 'App key';
    }

    public function run(): Result
    {
        $key = (string) config('app.key');

        if ($key === '') {
            return $this->fail('APP_KEY is not set - encryption, sessions and signed URLs are insecure.');
        }

        if (in_array($key, ['SomeRandomString', 'base64:SomeRandomString=', 'base64:' . base64_encode('SomeRandomString')], true)) {
            return $this->fail('APP_KEY is still a placeholder value.');
        }

        if (str_starts_with($key, 'base64:')) {
            $decoded = base64_decode(substr($key, 7), true);

            if ($decoded === false || strlen($decoded) < 16) {
                return $this->warn('APP_KEY does not decode to a 16+ byte key.');
            }

            return $this->pass('APP_KEY is set (' . strlen($decoded) . ' bytes).');
        }

        return $this->pass('APP_KEY is set (' . strlen($key) . ' bytes).');
    }
}