<?php

namespace BluedotBd\SanityCheck\Http\Middleware;

use BluedotBd\SanityCheck\Support\PayloadInspector;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Rejects requests whose payload contains PHP code-execution, shell command or
 * stream-wrapper signatures. Everything is configurable in
 * config/sanity-check.php ("middleware" section).
 */
class MaliciousPayloadFilter
{
    public function __construct(private PayloadInspector $inspector)
    {
    }

    /**
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $config = (array) config('sanity-check.middleware', []);

        if (! ($config['enabled'] ?? true)) {
            return $next($request);
        }

        if (! in_array($request->getMethod(), (array) ($config['methods'] ?? []), true)) {
            return $next($request);
        }

        foreach ((array) ($config['except_paths'] ?? []) as $pattern) {
            if ($request->is((string) $pattern)) {
                return $next($request);
            }
        }

        $threat = $this->inspector->findThreat((array) $request->all()) ?? $this->scanRawBody($request, $config);

        if ($threat === null) {
            return $next($request);
        }

        if ($config['log'] ?? true) {
            Log::warning('SanityCheck flagged a malicious payload', [
                'method' => $request->getMethod(),
                'url' => $request->fullUrl(),
                'ip' => $request->ip(),
                'field' => $threat['field'],
                'rule' => $threat['rule'],
            ]);
        }

        if (! ($config['block'] ?? true)) {
            return $next($request);
        }

        return $this->deny($request, $config);
    }

    /**
     * @param  array<string, mixed>  $config
     * @return array{field: string, rule: string}|null
     */
    private function scanRawBody(Request $request, array $config): ?array
    {
        $contentType = (string) $request->header('Content-Type', '');

        if (
            $request->isJson()
            || str_contains($contentType, 'multipart/form-data')
            || str_contains($contentType, 'application/x-www-form-urlencoded')
        ) {
            return null;
        }

        $body = $request->getContent();

        if (! is_string($body) || $body === '') {
            return null;
        }

        $rule = $this->inspector->detect($body);

        return $rule === null ? null : ['field' => '<raw body>', 'rule' => $rule];
    }

    /**
     * @param  array<string, mixed>  $config
     * @return \Illuminate\Http\JsonResponse|\Illuminate\Http\Response
     */
    private function deny(Request $request, array $config)
    {
        $status = (int) ($config['status'] ?? Response::HTTP_FORBIDDEN);
        $message = (string) ($config['message'] ?? 'Invalid request payload.');

        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json(['message' => $message], $status);
        }

        abort($status, $message);
    }
}