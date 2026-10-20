<?php

namespace BluedotBd\SanityCheck;

use BluedotBd\SanityCheck\Checks\Check;
use BluedotBd\SanityCheck\Results\Result;
use BluedotBd\SanityCheck\Support\ProbeClient;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Str;
use Throwable;

class SanityCheck
{
    /**
     * Run order: local posture first, remote exposure last.
     *
     * @var array<string, class-string<Check>>
     */
    private const CHECKS = [
        'horizon' => Checks\HorizonCheck::class,
        'totem' => Checks\TotemCheck::class,
        'totem_exposure' => Checks\TotemExposureCheck::class,
        'debug' => Checks\DebugModeCheck::class,
        'debugbar' => Checks\DebugbarCheck::class,
        'nightwatch' => Checks\NightwatchCheck::class,
        'log_viewer' => Checks\LogViewerCheck::class,
        'plugins' => Checks\EcosystemPluginsCheck::class,
        'ssl' => Checks\SslCertificateCheck::class,
        'app_key' => Checks\AppKeyCheck::class,
        'https' => Checks\HttpsCheck::class,
        'domain' => Checks\DomainEnvironmentCheck::class,
        'session' => Checks\SessionCookieCheck::class,
        'csrf' => Checks\CsrfCheck::class,
        'env_permissions' => Checks\EnvPermissionsCheck::class,
        'env_exposure' => Checks\EnvFileExposureCheck::class,
        'dashboards' => Checks\DashboardExposureCheck::class,
        'sensitive_files' => Checks\SensitiveFilesCheck::class,
        'security_headers' => Checks\SecurityHeadersCheck::class,
    ];

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(private Container $app, private array $config = [])
    {
    }

    /**
     * @param  array<int, string>|null  $only
     */
    public function run(?string $url = null, ?array $only = null, bool $skipRemote = false): Report
    {
        $probe = new ProbeClient((array) ($this->config['probe'] ?? []), $url);

        if ($skipRemote) {
            $probe->setSkipRemote(true);
        }

        $this->app->instance(ProbeClient::class, $probe);

        $results = [];

        foreach (self::CHECKS as $key => $class) {
            if (! ($this->config['checks'][$key]['enabled'] ?? true)) {
                continue;
            }

            if ($only !== null && ! in_array($key, $only, true)) {
                continue;
            }

            try {
                $results[] = $this->app->make($class)->run();
            } catch (Throwable $e) {
                $results[] = Result::fail($key, Str::headline($key), 'Check crashed: ' . $e->getMessage());
            }
        }

        return new Report($results, $probe->baseUrl());
    }

    /**
     * @return array<int, string>
     */
    public function keys(): array
    {
        return array_keys(self::CHECKS);
    }
}