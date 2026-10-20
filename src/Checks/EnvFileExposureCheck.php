<?php

namespace BluedotBd\SanityCheck\Checks;

use BluedotBd\SanityCheck\Results\Result;
use BluedotBd\SanityCheck\Support\ProbeClient;

class EnvFileExposureCheck extends Check
{
    public function __construct(private ProbeClient $probe)
    {
    }

    public function key(): string
    {
        return 'env_exposure';
    }

    public function label(): string
    {
        return '.env exposure';
    }

    public function run(): Result
    {
        $evidence = $this->publicEnvFiles();
        $probeProblem = null;

        if (! $this->probe->skipRemote()) {
            $probe = $this->probeRemoteEnv();

            if ($probe['leaked']) {
                $evidence[] = $probe['detail'];
            }

            $probeProblem = $probe['warning'];
        }

        if ($evidence === []) {
            if ($probeProblem !== null) {
                return $this->warn($probeProblem);
            }

            return $this->pass('Not present in public/ and not served over HTTP.');
        }

        return $this->fail(implode('; ', $evidence));
    }

    /**
     * .env files that must never live inside the public web root.
     *
     * @return array<int, string>
     */
    private function publicEnvFiles(): array
    {
        $found = [];

        foreach (glob(public_path('.env*')) ?: [] as $path) {
            if (is_file($path)) {
                $found[] = 'public/' . basename($path) . ' exists';
            }
        }

        return $found;
    }

    /**
     * @return array{leaked: bool, detail: string, warning: ?string}
     */
    private function probeRemoteEnv(): array
    {
        $url = $this->probe->url((string) config('sanity-check.checks.env_exposure.path', '/.env'));

        if ($url === null) {
            return ['leaked' => false, 'detail' => '', 'warning' => 'APP_URL is not configured - remote .env probe skipped.'];
        }

        $response = $this->probe->fetch($url);

        if ($response['error'] !== null) {
            return ['leaked' => false, 'detail' => '', 'warning' => "Could not probe {$url}: {$response['error']}"];
        }

        if ($response['status'] === 200 && self::bodyLooksLikeEnvFile($response['body'])) {
            return ['leaked' => true, 'detail' => "{$url} returned environment variables over HTTP", 'warning' => null];
        }

        return [
            'leaked' => false,
            'detail' => '',
            'warning' => $response['status'] === 200
                ? "{$url} returned HTTP 200 without environment contents - double check the web root."
                : null,
        ];
    }

    /**
     * A real .env download always exposes APP_KEY plus at least one other
     * setting, which keeps SPA / WAF catch-all pages from triggering this.
     */
    public static function bodyLooksLikeEnvFile(string $body): bool
    {
        if (preg_match('/^[ \t]*APP_KEY=[^\s]+/m', $body) !== 1) {
            return false;
        }

        return preg_match('/^[ \t]*(?:APP_ENV|APP_NAME|DB_CONNECTION|DB_PASSWORD|DB_USERNAME|MAIL_MAILER)=/m', $body) === 1;
    }
}