<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;

abstract class Check
{
    abstract public function key(): string;

    abstract public function label(): string;

    abstract public function run(): Result;

    protected function pass(string $detail): Result
    {
        return Result::pass($this->key(), $this->label(), $detail);
    }

    protected function warn(string $detail): Result
    {
        return Result::warn($this->key(), $this->label(), $detail);
    }

    protected function fail(string $detail): Result
    {
        return Result::fail($this->key(), $this->label(), $detail);
    }

    /**
     * Misconfigurations that only matter in production fail there and warn
     * everywhere else, so local runs stay readable.
     */
    protected function productionIssue(string $detail): Result
    {
        if ($this->isProduction()) {
            return $this->fail($detail);
        }

        return $this->warn($detail . ' (not production)');
    }

    protected function isProduction(): bool
    {
        return app()->environment('production');
    }
}