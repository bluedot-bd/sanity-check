<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Master switch
    |--------------------------------------------------------------------------
    |
    | When disabled the middleware is not pushed onto the HTTP stack, the
    | command is still registered but reports every check as skipped.
    |
    */

    'enabled' => env('SANITY_CHECK_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Payload filter (eval / shell_exec / command injection)
    |--------------------------------------------------------------------------
    |
    | Requests carrying PHP code-execution or shell signatures are rejected
    | before they reach a controller. Set "block" to false to only log them.
    |
    */

    'middleware' => [

        'enabled' => env('SANITY_CHECK_MIDDLEWARE', true),

        // Push the filter onto the global HTTP stack (all routes).
        'global' => true,

        // false = log the hit but let the request through.
        'block' => true,

        // HTTP verbs whose payload is inspected.
        'methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],

        // Route patterns that are allowed to carry such payloads (e.g. "totem/*").
        'except_paths' => [],

        // Response returned when a payload is blocked.
        'status' => 403,
        'message' => 'Invalid request payload.',

        // Log every blocked / flagged request.
        'log' => true,

        // Fields that may legitimately look like a payload (user secrets).
        'ignored_keys' => [
            'password',
            'password_confirmation',
            'current_password',
            'new_password',
            'old_password',
        ],

        // Rule label => regular expression. Add your own rules here.
        'patterns' => [
            'php_code_execution' => '/(?<!\w)(?:eval|assert|create_function|shell_exec|exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(/i',
            'php_obfuscation' => '/(?<!\w)(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(/i',
            'php_superglobal' => '/\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[/i',
            'php_tag' => '/<\?(?:php|=)/i',
            'stream_wrapper' => '/(?<!\w)(?:php|phar|expect|zip|glob|data):\/\//i',
            'shell_command' => '/\b(?:rm\s+-[rf]{1,2}\b|chmod\s+[0-7]{3,4}\b|nc\s+-[ec]\b|netcat\b|(?:ba|z)?sh\s+-c\b)/i',
            'sensitive_path' => '/\/bin\/(?:ba|z)?sh\b|\/etc\/(?:passwd|shadow)\b/i',
            'backtick_command' => '/`[^`\r\n]{0,200}(?:[;|&]|\$\(|\b(?:rm|mv|cp|cat|ls|whoami|id|curl|wget|nc|bash|sh|python|perl|php)\b)[^`\r\n]{0,200}`/i',
            'command_substitution' => '/\$\([^)\r\n]{0,200}(?:[;|&]|\b(?:rm|mv|cp|cat|ls|whoami|id|curl|wget|nc|bash|sh|python|perl)\b)[^)\r\n]{0,200}\)/i',
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Remote probe
    |--------------------------------------------------------------------------
    |
    | Used by the exposure checks. "url" defaults to config('app.url').
    |
    */

    'probe' => [
        'url' => env('SANITY_CHECK_URL'),
        'skip_remote' => env('SANITY_CHECK_SKIP_REMOTE', false),
        'connect_timeout' => 3,
        'timeout' => 5,
        'user_agent' => 'SanityCheck/1.0',
    ],

    /*
    |--------------------------------------------------------------------------
    | Checks
    |--------------------------------------------------------------------------
    |
    | Local checks read the application state, remote checks probe the public
    | site. Disable any check with "enabled" => false.
    |
    */

    'checks' => [

        'horizon' => [
            'enabled' => true,
        ],

        'totem' => [
            'enabled' => true,
            'max_result_age_hours' => 24,
        ],

        'totem_exposure' => [
            'enabled' => true,
            'path' => env('TOTEM_WEB_ROUTE_PREFIX', 'totem'),
            'signature' => '~vendor/totem/css/app\.css|<title>\s*Totem~i',
        ],

        'debug' => [
            'enabled' => true,
        ],

        'debugbar' => [
            'enabled' => true,
            // Remote path probed when the package is installed.
            'path' => '_debugbar/open',
        ],

        'nightwatch' => [
            'enabled' => true,
        ],

        'log_viewer' => [
            'enabled' => true,
            // Falls back to config('log-viewer.route_path') when the package is installed.
            'path' => env('LOG_VIEWER_PATH', 'log-viewer'),
            'signature' => '~log-viewer|log_viewer|Log Viewer~i',
        ],

        'ssl' => [
            'enabled' => true,
            // Warn this many days before the certificate expires.
            'warn_days' => env('SANITY_CHECK_SSL_WARN_DAYS', 3),
            // Disable only for self-signed setups you control.
            'verify_peer' => env('SANITY_CHECK_SSL_VERIFY', true),
        ],

        'plugins' => [
            'enabled' => true,
            /*
             * Laravel ecosystem packages that are commonly left in a wrong
             * state on production. "expect" is what production should look
             * like: enabled = should be running (monitoring), disabled = must
             * be off / gated, ignore = reported only (has a dedicated check).
             */
            'packages' => [
                'nightwatch' => [
                    'class' => 'Laravel\\Nightwatch\\Nightwatch',
                    'config' => 'nightwatch.enabled',
                    'expect' => 'enabled',
                ],
                'pulse' => [
                    'class' => 'Laravel\\Pulse\\Pulse',
                    'config' => 'pulse.enabled',
                    'expect' => 'disabled',
                ],
                'telescope' => [
                    'class' => 'Laravel\\Telescope\\Telescope',
                    'config' => 'telescope.enabled',
                    'expect' => 'disabled',
                ],
                'log-viewer' => [
                    'class' => 'Opcodes\\LogViewer\\LogViewerServiceProvider',
                    'config' => 'log-viewer.enabled',
                    'expect' => 'disabled',
                ],
                'debugbar' => [
                    'class' => 'Barryvdh\\Debugbar\\ServiceProvider',
                    'config' => 'debugbar.enabled',
                    'expect' => 'disabled',
                ],
                'ignition' => [
                    'class' => 'Spatie\\Ignition\\IgnitionServiceProvider',
                    'config' => null,
                    'expect' => 'ignore',
                ],
                'horizon' => [
                    'class' => 'Laravel\\Horizon\\Horizon',
                    'config' => null,
                    'expect' => 'ignore',
                ],
                'totem' => [
                    'class' => 'Studio\\Totem\\Totem',
                    'config' => null,
                    'expect' => 'ignore',
                ],
            ],
        ],

        'app_key' => [
            'enabled' => true,
        ],

        'https' => [
            'enabled' => true,
        ],

        'domain' => [
            'enabled' => true,
        ],

        'session' => [
            'enabled' => true,
        ],

        'csrf' => [
            'enabled' => true,
        ],

        'env_permissions' => [
            'enabled' => true,
        ],

        'env_exposure' => [
            'enabled' => true,
            'path' => '/.env',
        ],

        'dashboards' => [
            'enabled' => true,
            'targets' => [
                'horizon' => [
                    'enabled' => true,
                    'label' => 'Horizon dashboard',
                    'path' => env('HORIZON_PATH', 'horizon'),
                    'signature' => '~id="horizon"|Laravel</strong>\s*Horizon|window\.Horizon~i',
                ],
                'totem' => [
                    'enabled' => false,
                    'label' => 'Totem dashboard',
                    'path' => env('TOTEM_WEB_ROUTE_PREFIX', 'totem'),
                    'signature' => '~/vendor/totem/css/app\.css|<title>\s*Totem~i',
                    // Covered by the dedicated "totem_exposure" check so that a
                    // publicly readable Totem can trigger maintenance mode.
                ],
                'telescope' => [
                    'enabled' => true,
                    'label' => 'Telescope',
                    'path' => 'telescope',
                    'signature' => '~/telescope/css|Telescope</title>~i',
                ],
            ],
        ],

        'sensitive_files' => [
            'enabled' => true,
            // path => signature. A null signature means "must look like a .env file".
            'paths' => [
                '/.env.backup' => null,
                '/.env.old' => null,
                '/.env.local' => null,
                '/.git/config' => '~\[core\]|repositoryformatversion~i',
                '/storage/logs/laravel.log' => '~\.(?:EMERGENCY|ALERT|CRITICAL|ERROR|WARNING):\s~m',
                '/phpinfo.php' => '~<title>phpinfo\(\)</title>|PHP Version =>~i',
            ],
            // Responding paths that are not credentials but still a leak.
            'optional_paths' => [
                '/_ignition/health-check' => '~can_execute_commands~i',
                '/composer.json' => '~"(?:require|require-dev)"\s*:~i',
            ],
        ],

        'security_headers' => [
            'enabled' => true,
            'required' => [
                'x-frame-options',
                'x-content-type-options',
                'content-security-policy',
                'strict-transport-security',
            ],
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Notifications
    |--------------------------------------------------------------------------
    |
    | Sent when at least one result has a status listed in "statuses".
    | Identical reports are throttled for "throttle_seconds".
    |
    */

    'notifications' => [

        'enabled' => env('SANITY_CHECK_NOTIFY', false),

        'statuses' => ['fail'],

        'throttle_seconds' => env('SANITY_CHECK_NOTIFY_THROTTLE', 3600),

        'channels' => [

            'mail' => [
                'enabled' => env('SANITY_CHECK_MAIL', false),
                'to' => array_values(array_filter(array_map('trim', explode(',', (string) env('SANITY_CHECK_MAIL_TO', ''))))),
                'subject' => env('SANITY_CHECK_MAIL_SUBJECT', 'SanityCheck security report'),
            ],

            'webhook' => [
                'enabled' => env('SANITY_CHECK_WEBHOOK', false),
                'url' => env('SANITY_CHECK_WEBHOOK_URL'),
                'headers' => [],
                'timeout' => 5,
            ],

            'slack' => [
                'enabled' => env('SANITY_CHECK_SLACK', false),
                'webhook_url' => env('SANITY_CHECK_SLACK_WEBHOOK'),
                'channel' => env('SANITY_CHECK_SLACK_CHANNEL'),
                'timeout' => 5,
            ],

            'discord' => [
                'enabled' => env('SANITY_CHECK_DISCORD', false),
                'webhook_url' => env('SANITY_CHECK_DISCORD_WEBHOOK'),
                'timeout' => 5,
            ],

        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Actions
    |--------------------------------------------------------------------------
    |
    | What to do when checks fail. "trigger_on" lists the check keys that put
    | the application into maintenance mode ("*" means any failure).
    |
    */

    'actions' => [

        'maintenance' => [
            'enabled' => env('SANITY_CHECK_MAINTENANCE', true),
            // Totem can run arbitrary artisan commands, so a public Totem is
            // treated like a public .env: take the site down immediately.
            'trigger_on' => ['env_exposure', 'totem_exposure', 'debug', 'debugbar'],
            'secret' => env('SANITY_CHECK_MAINTENANCE_SECRET'),
            'retry' => env('SANITY_CHECK_MAINTENANCE_RETRY'),
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Security advisories
    |--------------------------------------------------------------------------
    |
    | "sanity-check:advisories" sends every installed package to
    | https://packagist.org/api/security-advisories/ and warns about the
    | advisories that affect the installed version. Scheduled once a day.
    |
    */

    'advisories' => [
        'url' => env('SANITY_CHECK_ADVISORIES_URL', 'https://packagist.org/api/security-advisories/'),
        'timeout' => 10,
        'batch_size' => 50,
        'include_dev' => env('SANITY_CHECK_ADVISORIES_INCLUDE_DEV', true),
        // Advisory ids (e.g. PKSA-xxxx-xxxx-xxxx) to accept as known risk.
        'ignore' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | npm advisories
    |--------------------------------------------------------------------------
    |
    | "sanity-check:npm-advisories" sends the packages from package-lock.json
    | (or package.json) to https://registry.npmjs.org/-/npm/v1/security/advisories/bulk
    | and warns about the advisories that affect the installed version.
    |
    */

    'npm_advisories' => [
        'url' => env('SANITY_CHECK_NPM_ADVISORIES_URL', 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'),
        // Defaults to base_path('package.json').
        'path' => env('SANITY_CHECK_PACKAGE_JSON'),
        'timeout' => 15,
        'batch_size' => 50,
        'include_dev' => env('SANITY_CHECK_NPM_INCLUDE_DEV', true),
        // Severities to report: critical, high, moderate, low (empty = all).
        'severities' => ['critical', 'high', 'moderate', 'low'],
        // Advisory ids to accept as known risk.
        'ignore' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Schedule
    |--------------------------------------------------------------------------
    */

    'schedule' => [
        'enabled' => env('SANITY_CHECK_SCHEDULE', true),
        'cron' => env('SANITY_CHECK_SCHEDULE_CRON', '*/5 * * * *'),
        'environments' => ['production'],
        'without_overlapping' => true,
        'run_in_background' => true,

        // Daily advisories scan (sanity-check:advisories).
        'advisories_enabled' => env('SANITY_CHECK_ADVISORIES_SCHEDULE', true),
        'advisories_cron' => env('SANITY_CHECK_ADVISORIES_CRON', '0 3 * * *'),

        // Daily npm advisories scan (sanity-check:npm-advisories).
        'npm_advisories_enabled' => env('SANITY_CHECK_NPM_ADVISORIES_SCHEDULE', true),
        'npm_advisories_cron' => env('SANITY_CHECK_NPM_ADVISORIES_CRON', '15 3 * * *'),
    ],

];