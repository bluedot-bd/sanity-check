<?php

namespace BluedotBd\SanityCheck;

use BluedotBd\SanityCheck\Actions\MaintenanceAction;
use BluedotBd\SanityCheck\Console\Commands\NpmAdvisoriesCommand;
use BluedotBd\SanityCheck\Console\Commands\SanityCheckCommand;
use BluedotBd\SanityCheck\Console\Commands\SecurityAdvisoriesCommand;
use BluedotBd\SanityCheck\Http\Middleware\MaliciousPayloadFilter;
use BluedotBd\SanityCheck\Notifications\Notifier;
use BluedotBd\SanityCheck\Support\PayloadInspector;
use BluedotBd\SanityCheck\Support\ProbeClient;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Support\ServiceProvider;

class SanityCheckServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/sanity-check.php', 'sanity-check');

        $this->app->singleton(PayloadInspector::class, function ($app) {
            $config = (array) $app['config']->get('sanity-check.middleware', []);

            return new PayloadInspector(
                (array) ($config['patterns'] ?? []),
                (array) ($config['ignored_keys'] ?? [])
            );
        });

        $this->app->singleton(ProbeClient::class, function ($app) {
            return new ProbeClient((array) $app['config']->get('sanity-check.probe', []));
        });

        $this->app->singleton(SanityCheck::class, function ($app) {
            return new SanityCheck($app, (array) $app['config']->get('sanity-check', []));
        });

        $this->app->singleton(Notifier::class, function ($app) {
            return new Notifier($app, (array) $app['config']->get('sanity-check.notifications', []));
        });

        $this->app->singleton(MaintenanceAction::class, function ($app) {
            return new MaintenanceAction($app, (array) $app['config']->get('sanity-check.actions.maintenance', []));
        });
    }

    public function boot(): void
    {
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'sanity-check');

        $this->publishes([
            __DIR__ . '/../config/sanity-check.php' => config_path('sanity-check.php'),
        ], 'sanity-check-config');

        if (! $this->app['config']->get('sanity-check.enabled', true)) {
            return;
        }

        $this->registerMiddleware();

        if ($this->app->runningInConsole()) {
            $this->commands([SanityCheckCommand::class, SecurityAdvisoriesCommand::class, NpmAdvisoriesCommand::class]);

            $this->registerSchedule();
        }
    }

    private function registerMiddleware(): void
    {
        $config = (array) $this->app['config']->get('sanity-check.middleware', []);

        if (! ($config['enabled'] ?? true) || ! ($config['global'] ?? true)) {
            return;
        }

        $this->app->make(HttpKernel::class)->prependMiddleware(MaliciousPayloadFilter::class);
    }

    private function registerSchedule(): void
    {
        $config = (array) $this->app['config']->get('sanity-check.schedule', []);

        if (! ($config['enabled'] ?? false)) {
            return;
        }

        $this->callAfterResolving(Schedule::class, function (Schedule $schedule) use ($config) {
            $this->scheduleCommand($schedule, 'sanity-check:run', (string) ($config['cron'] ?? '*/5 * * * *'), $config);

            if ($config['advisories_enabled'] ?? true) {
                $this->scheduleCommand(
                    $schedule,
                    'sanity-check:advisories',
                    (string) ($config['advisories_cron'] ?? '0 3 * * *'),
                    $config
                );
            }

            if ($config['npm_advisories_enabled'] ?? true) {
                $this->scheduleCommand(
                    $schedule,
                    'sanity-check:npm-advisories',
                    (string) ($config['npm_advisories_cron'] ?? '15 3 * * *'),
                    $config
                );
            }
        });
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private function scheduleCommand(Schedule $schedule, string $command, string $cron, array $config): void
    {
        $event = $schedule->command($command)->cron($cron);

        if ($config['without_overlapping'] ?? true) {
            $event->withoutOverlapping();
        }

        if ($config['run_in_background'] ?? true) {
            $event->runInBackground();
        }

        if (! empty($config['environments'])) {
            $event->environments((array) $config['environments']);
        }
    }
}