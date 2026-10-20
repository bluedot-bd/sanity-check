# SanityCheck

[![Latest Version on Packagist](https://img.shields.io/packagist/v/bluedot-bd/sanity-check.svg)](https://packagist.org/packages/bluedot-bd/sanity-check)
[![Total Downloads](https://img.shields.io/packagist/dt/bluedot-bd/sanity-check.svg)](https://packagist.org/packages/bluedot-bd/sanity-check)
[![License](https://img.shields.io/packagist/l/bluedot-bd/sanity-check.svg)](https://packagist.org/packages/bluedot-bd/sanity-check)

Security sanity checks and a malicious payload filter for Laravel applications.

## Why SanityCheck?

We all know what a product should avoid: debug mode left on, an `.env` sitting in
the web root, a debugbar or log viewer anyone can open, an expired certificate, a
queue worker that quietly died, a dashboard that was `auth`-protected last month
and is not anymore.

And then life happens. A deploy copies the wrong file, a server gets rebuilt, a
package is re-enabled "just for a minute" while debugging an incident, the person
who knew about that one `.env` backup leaves the team. The config that was
correct six months ago is not correct today, and nobody finds out until a
customer, a crawler, or an attacker does. By then someone has to log into five
dashboards to figure out what broke.

SanityCheck exists so most of those checks run for you:

- basic payload filtering on the way in, with the rules in a config file,
- `php artisan sanity-check:run` (manually or from the scheduler) tells you what
  is off right now,
- failures go to mail, Slack, Discord or your own webhook, so you hear about it
  first,
- and the action you configured - maintenance mode, for example - happens
  without anyone being awake.

**It does not guarantee security.** It cannot review business logic,
authorisation rules, infrastructure, or a determined attacker. What it does is
catch the basic, boring, recurring faults - the ones that keep happening - so you
are not the one who finds out last.

Two capabilities, one config file:


1. **`MaliciousPayloadFilter` middleware** — rejects requests whose payload contains
   `eval`, `shell_exec`, `exec`, `system`, backticks, `$(...)`, stream wrappers,
   PHP tags and similar code-execution signatures (all pattern-driven).
2. **`sanity-check:run` command** — a scheduled self-check of the application's
   security posture (Horizon, Totem, Nightwatch, debug/debugbar, APP_KEY, HTTPS,
   domain vs. environment, session cookies, CSRF, TLS expiry, `.env` exposure,
   admin dashboards, log viewer, sensitive public files, ecosystem plugins and
   security headers). Failures can trigger notifications and actions such as
   enabling maintenance mode.

## Installation

```bash
composer require bluedot-bd/sanity-check
```

That is all that is required - Laravel package discovery registers
`BluedotBd\SanityCheck\SanityCheckServiceProvider` automatically.

Publish the config file to tune the checks, channels and actions:

```bash
php artisan vendor:publish --tag=sanity-check-config
```

- Packagist: <https://packagist.org/packages/bluedot-bd/sanity-check>
- Source: <https://github.com/bluedot-bd/sanity-check>

Requires PHP 8.2+ and Laravel 11 or 12.

### Working from source

This application also ships the package inside `packages/sanity-check` and wires
it through a Composer path repository, so local changes are picked up without a
release:

```json
"repositories": [
    { "type": "path", "url": "packages/sanity-check", "options": { "symlink": false } }
]
```

Because Composer copies the package into `vendor/` on Windows (junctions are not
available on every filesystem), re-sync after changing package code:

```bash
composer reinstall bluedot-bd/sanity-check
```

## Payload filter

The middleware is prepended to the global HTTP stack, so it runs before any
controller/session/database work:

```php
// config/sanity-check.php
'middleware' => [
    'enabled' => true,
    'global' => true,       // auto-register; false = add it to App\Http\Kernel yourself
    'block' => true,        // false = log only
    'methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    'except_paths' => [],   // e.g. ['totem/*']
    'status' => 403,
    'message' => 'Invalid request payload.',
    'log' => true,
    'ignored_keys' => ['password', 'password_confirmation'],
    'patterns' => [
        'php_code_execution' => '/(?<!\w)(?:eval|assert|shell_exec|exec|system)\s*\(/i',
        // add your own rules here
    ],
],
```

Blocked requests are logged with the method, URL, IP, offending field and the
matched rule — never the payload value itself.

## Checks

Run manually:

```bash
php artisan sanity-check:run
php artisan sanity-check:run --url=https://example.com --dry-run
php artisan sanity-check:run --only=env_exposure,dashboards --json
php artisan security:check          # command alias
```

| Key | What it checks |
| --- | --- |
| `horizon` | Horizon master supervisors exist and are not all paused |
| `totem` | Totem enabled, active tasks, tasks registered on the scheduler, latest `task_results.ran_at` |
| `debug` | `APP_DEBUG` is off outside local/testing |
| `debugbar` | Debugbar not enabled in production and `/_debugbar/open` not reachable |
| `nightwatch` | Nightwatch installed but disabled in production (monitoring gap) or missing `NIGHTWATCH_TOKEN` |
| `log_viewer` | `log-viewer` route not readable anonymously (`403`/`302`/`404` pass) |
| `plugins` | Inventory of Laravel ecosystem packages with the expected production state (`enabled` / `disabled` / `ignore`) |
| `ssl` | TLS certificate expiry — WARN 3 days before, FAIL once expired |
| `app_key` | `APP_KEY` present, not a placeholder, decodes to 16+ bytes |
| `https` | `APP_URL` uses HTTPS |
| `domain` | `APP_URL` looks like a real public domain while `APP_ENV` is not production (or production with a non-public host) |
| `session` | `secure`, `http_only`, `same_site` cookie flags |
| `csrf` | `VerifyCsrfToken` is present in the `web` middleware group |
| `env_permissions` | `.env` is not world-readable (POSIX only) |
| `env_exposure` | No `.env*` in `public/` and `GET {url}/.env` does not return environment contents |
| `dashboards` | `/horizon`, `/totem`, `/telescope` are not anonymously readable |
| `sensitive_files` | `.git/config`, old `.env` copies, logs, phpinfo, Ignition, composer.json |
| `security_headers` | `X-Frame-Options`/CSP, `nosniff`, CSP and HSTS on the homepage |

Every check can be disabled with `'enabled' => false` and remote probes can be
skipped per run with `--skip-remote` (or globally with `SANITY_CHECK_SKIP_REMOTE`).

### Ecosystem plugins

`checks.plugins.packages` maps a package to its expected production state:

```php
'plugins' => [
    'enabled' => true,
    'packages' => [
        'nightwatch' => ['class' => 'Laravel\Nightwatch\Nightwatch', 'config' => 'nightwatch.enabled', 'expect' => 'enabled'],
        'pulse' => ['class' => 'Laravel\Pulse\Pulse', 'config' => 'pulse.enabled', 'expect' => 'disabled'],
        'telescope' => ['class' => 'Laravel\Telescope\Telescope', 'config' => 'telescope.enabled', 'expect' => 'disabled'],
        'log-viewer' => ['class' => 'Opcodes\LogViewer\LogViewerServiceProvider', 'config' => 'log-viewer.enabled', 'expect' => 'disabled'],
        'debugbar' => ['class' => 'Barryvdh\Debugbar\ServiceProvider', 'config' => 'debugbar.enabled', 'expect' => 'disabled'],
    ],
],
```

`expect` is only enforced in production: `disabled` packages that are enabled fail
the check, `enabled` packages that are off only warn. Add any other package by its
service provider class and config key.

### TLS certificate

```php
'ssl' => [
    'enabled' => true,
    'warn_days' => env('SANITY_CHECK_SSL_WARN_DAYS', 3),
    'verify_peer' => env('SANITY_CHECK_SSL_VERIFY', true),
],
```

Reads the certificate over TLS (`openssl_x509_parse`) from `APP_URL`, warns
`warn_days` before expiry and fails once expired. `verify_peer` exists only for
self-signed environments you control.

### Domain vs. environment

`checks.domain` compares `APP_URL` with the application environment:

| `APP_URL` host | `APP_ENV` | Result |
| --- | --- | --- |
| real public domain | `production` | PASS |
| real public domain | anything else | **WARN** - a public domain is served with dev/staging settings |
| `localhost`, `*.test`, `*.local`, `*.example`, IP | `production` | **WARN** - production points at a non-public host |
| `localhost`, `*.test`, `*.local`, `*.example`, IP | anything else | PASS |

This is the classic "someone rebuilt the server and forgot `APP_ENV`" case: the
domain is real, customers are on it, but the app thinks it is local - so debug
pages, verbose errors and test mailers are live.

## Notifications

Sent when a result matches `notifications.statuses` (default: `fail`). Identical
reports are throttled by `throttle_seconds` (default one hour).

```php
'notifications' => [
    'enabled' => env('SANITY_CHECK_NOTIFY', false),
    'statuses' => ['fail'],
    'throttle_seconds' => 3600,
    'channels' => [
        'mail' => ['enabled' => true, 'to' => ['ops@example.com'], 'subject' => 'SanityCheck'],
        'webhook' => ['enabled' => true, 'url' => env('SANITY_CHECK_WEBHOOK_URL'), 'headers' => []],
        'slack' => ['enabled' => true, 'webhook_url' => env('SANITY_CHECK_SLACK_WEBHOOK')],
        'discord' => ['enabled' => true, 'webhook_url' => env('SANITY_CHECK_DISCORD_WEBHOOK')],
    ],
],
```

Payloads: JSON (`webhook`), Slack `attachments`, Discord `embeds`, and a Mailable
with the full report. Each channel is isolated — one failing channel never blocks
the others.

## Actions

```php
'actions' => [
    'maintenance' => [
        'enabled' => env('SANITY_CHECK_MAINTENANCE', true),
        // Which failing check keys put the site into maintenance. '*' = any failure.
        'trigger_on' => ['env_exposure', 'debug', 'debugbar'],
        'secret' => env('SANITY_CHECK_MAINTENANCE_SECRET'), // bypass URL
        'retry' => env('SANITY_CHECK_MAINTENANCE_RETRY'),
    ],
],
```

`--dry-run` reports what would happen without touching the maintenance state.
`--no-notify` skips notifications.

## Scheduling

Registered by the package when running in console:

```php
'schedule' => [
    'enabled' => env('SANITY_CHECK_SCHEDULE', true),
    'cron' => env('SANITY_CHECK_SCHEDULE_CRON', '*/5 * * * *'),
    'environments' => ['production'],
    'without_overlapping' => true,
    'run_in_background' => true,
],
```

## Tests

```bash
php artisan test --filter=SanityCheck
```

## Maintainers

Bluedot Technology Ltd. - [saiful@bluedot.ltd](mailto:saiful@bluedot.ltd)

Bugs and feature requests: <https://github.com/bluedot-bd/sanity-check/issues>

## License

MIT - see [LICENSE](LICENSE).
