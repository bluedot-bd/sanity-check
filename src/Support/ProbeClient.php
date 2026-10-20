<?php

namespace BluedotBd\SanityCheck\Support;

use Illuminate\Support\Facades\Http;
use Throwable;

class ProbeClient
{
    private ?string $url;

    private bool $skipRemote;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(private array $config, ?string $url = null)
    {
        $candidate = rtrim((string) ($url ?: ($config['url'] ?? null) ?: config('app.url')), '/');

        $this->url = $candidate === '' ? null : $candidate;
        $this->skipRemote = (bool) ($config['skip_remote'] ?? false);
    }

    public function setSkipRemote(bool $skip): void
    {
        $this->skipRemote = $skip;
    }

    public function skipRemote(): bool
    {
        return $this->skipRemote;
    }

    public function baseUrl(): ?string
    {
        return $this->url;
    }

    public function url(string $path): ?string
    {
        if ($this->url === null) {
            return null;
        }

        return $this->url . '/' . ltrim($path, '/');
    }

    public function isHttps(): bool
    {
        return $this->url !== null && str_starts_with($this->url, 'https://');
    }

    /**
     * @return array{status: int, body: string, headers: array<string, array<int, string>>, error: ?string}
     */
    public function fetch(string $url, bool $followRedirects = false): array
    {
        try {
            $request = Http::connectTimeout((int) ($this->config['connect_timeout'] ?? 3))
                ->timeout((int) ($this->config['timeout'] ?? 5))
                ->withHeaders([
                    'Accept' => 'text/plain',
                    'User-Agent' => (string) ($this->config['user_agent'] ?? 'SanityCheck/1.0'),
                ]);

            if (! $followRedirects) {
                $request = $request->withoutRedirecting();
            }

            $response = $request->get($url);

            return [
                'status' => $response->status(),
                'body' => (string) $response->body(),
                'headers' => $response->headers(),
                'error' => null,
            ];
        } catch (Throwable $e) {
            return ['status' => 0, 'body' => '', 'headers' => [], 'error' => $e->getMessage()];
        }
    }
}