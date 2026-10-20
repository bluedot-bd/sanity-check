<?php

namespace BluedotBd\SanityCheck;

use BluedotBd\SanityCheck\Results\Result;

final class Report
{
    /**
     * @param  array<int, Result>  $results
     */
    public function __construct(
        public readonly array $results,
        public readonly ?string $url = null,
    ) {
    }

    /**
     * @return array<int, Result>
     */
    public function failures(): array
    {
        return array_values(array_filter($this->results, fn (Result $result) => $result->isFailure()));
    }

    /**
     * @return array<int, Result>
     */
    public function warnings(): array
    {
        return array_values(array_filter($this->results, fn (Result $result) => $result->isWarning()));
    }

    public function hasFailures(): bool
    {
        return $this->failures() !== [];
    }

    /**
     * @return array<int, string>
     */
    public function failureKeys(): array
    {
        return array_map(fn (Result $result) => $result->key, $this->failures());
    }

    /**
     * @return array{pass: int, warn: int, fail: int, total: int}
     */
    public function summary(): array
    {
        $counts = [Result::PASS => 0, Result::WARN => 0, Result::FAIL => 0];

        foreach ($this->results as $result) {
            $counts[$result->status] = ($counts[$result->status] ?? 0) + 1;
        }

        return [
            'pass' => $counts[Result::PASS],
            'warn' => $counts[Result::WARN],
            'fail' => $counts[Result::FAIL],
            'total' => count($this->results),
        ];
    }

    public function fingerprint(): string
    {
        $parts = array_map(fn (Result $result) => $result->key . ':' . $result->status, $this->results);

        sort($parts);

        return md5(implode('|', $parts));
    }

    /**
     * @return array{url: ?string, summary: array{pass: int, warn: int, fail: int, total: int}, results: array<int, array{key: string, label: string, status: string, detail: string}>}
     */
    public function toArray(): array
    {
        return [
            'url' => $this->url,
            'summary' => $this->summary(),
            'results' => array_map(fn (Result $result) => $result->toArray(), $this->results),
        ];
    }
}