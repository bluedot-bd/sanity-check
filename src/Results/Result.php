<?php

namespace BluedotBd\SanityCheck\Results;

final class Result
{
    public const PASS = 'pass';

    public const WARN = 'warn';

    public const FAIL = 'fail';

    public function __construct(
        public readonly string $key,
        public readonly string $label,
        public readonly string $status,
        public readonly string $detail,
    ) {
    }

    public static function pass(string $key, string $label, string $detail): self
    {
        return new self($key, $label, self::PASS, $detail);
    }

    public static function warn(string $key, string $label, string $detail): self
    {
        return new self($key, $label, self::WARN, $detail);
    }

    public static function fail(string $key, string $label, string $detail): self
    {
        return new self($key, $label, self::FAIL, $detail);
    }

    public function isFailure(): bool
    {
        return $this->status === self::FAIL;
    }

    public function isWarning(): bool
    {
        return $this->status === self::WARN;
    }

    /**
     * @return array{key: string, label: string, status: string, detail: string}
     */
    public function toArray(): array
    {
        return [
            'key' => $this->key,
            'label' => $this->label,
            'status' => $this->status,
            'detail' => $this->detail,
        ];
    }
}