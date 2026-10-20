<?php

namespace BluedotBd\SanityCheck\Support;

/**
 * Pattern matcher used by the payload filter and by the middleware tests.
 * Kept free of framework dependencies so it can be unit tested directly.
 */
class PayloadInspector
{
    /** @var array<string, string> */
    private array $patterns;

    /** @var array<int, string> */
    private array $ignoredKeys;

    /**
     * @param  array<string, string>  $patterns  rule label => regular expression
     * @param  array<int, string>  $ignoredKeys
     */
    public function __construct(array $patterns, array $ignoredKeys = [])
    {
        $this->patterns = $patterns;
        $this->ignoredKeys = array_map('strtolower', $ignoredKeys);
    }

    /**
     * Return the name of the rule matching the value, or null when it is clean.
     */
    public function detect(string $value): ?string
    {
        if ($value === '') {
            return null;
        }

        foreach ($this->patterns as $rule => $pattern) {
            if (@preg_match((string) $pattern, $value) === 1) {
                return $rule;
            }
        }

        return null;
    }

    /**
     * Walk the payload (including nested arrays) and return the first offending
     * field together with the rule that matched.
     *
     * @param  array<mixed>  $input
     * @return array{field: string, rule: string}|null
     */
    public function findThreat(array $input): ?array
    {
        foreach ($input as $key => $value) {
            $key = (string) $key;

            if ($this->isIgnoredKey($key)) {
                continue;
            }

            $rule = $this->detect($key);

            if ($rule !== null) {
                return ['field' => $key, 'rule' => $rule];
            }

            if (is_array($value)) {
                $nested = $this->findThreat($value);

                if ($nested !== null) {
                    return ['field' => $key . '.' . $nested['field'], 'rule' => $nested['rule']];
                }

                continue;
            }

            if (is_string($value) && ($rule = $this->detect($value)) !== null) {
                return ['field' => $key, 'rule' => $rule];
            }
        }

        return null;
    }

    private function isIgnoredKey(string $key): bool
    {
        return in_array(strtolower($key), $this->ignoredKeys, true);
    }
}