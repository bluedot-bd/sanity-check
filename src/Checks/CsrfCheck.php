<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use ReflectionProperty;
use Throwable;

class CsrfCheck extends Check
{
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

        $hasCsrf = collect($web)->contains(fn ($middleware) => str_contains((string) $middleware, 'VerifyCsrfToken'));

        if (! $hasCsrf) {
            return $this->fail('VerifyCsrfToken is missing from the web middleware group.');
        }

        return $this->pass('VerifyCsrfToken is active on the web group.');
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