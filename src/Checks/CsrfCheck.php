<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use ReflectionProperty;
use Throwable;

class CsrfCheck extends Check
{
    /**
     * Laravel 11 renamed VerifyCsrfToken to PreventRequestForgery and kept the
     * old name as a deprecated alias, so every name has to be accepted.
     *
     * @var array<int, string>
     */
    private const MIDDLEWARE = [
        'PreventRequestForgery',
        'ValidateCsrfToken',
        'VerifyCsrfToken',
    ];

    public function key(): string
    {
        return 'csrf';
    }

    public function label(): string
    {
        return 'CSRF protection';
    }

    public function run(): Result
    {
        $groups = $this->middlewareGroups();
        $web = $groups['web'] ?? null;

        if ($web === null) {
            return $this->warn('Could not inspect the web middleware group.');
        }

        $found = static::csrfMiddleware($web);

        if ($found === null) {
            return $this->fail('No CSRF middleware (PreventRequestForgery) is in the web middleware group.');
        }

        return $this->pass("{$found} is active on the web group.");
    }

    /**
     * Name of the CSRF middleware in the given group, if any.
     *
     * @param  array<int, string>  $middleware
     */
    public static function csrfMiddleware(array $middleware): ?string
    {
        foreach ($middleware as $class) {
            foreach (self::MIDDLEWARE as $name) {
                if (str_contains((string) $class, $name)) {
                    return $name;
                }
            }
        }

        return null;
    }

    /**
     * @return array<string, array<int, string>>
     */
    private function middlewareGroups(): array
    {
        try {
            $kernel = app(HttpKernel::class);
            $property = new ReflectionProperty($kernel, 'middlewareGroups');
            $property->setAccessible(true);

            return (array) $property->getValue($kernel);
        } catch (Throwable $e) {
            return [];
        }
    }
}