<?php

namespace BluedotBd\SanityCheck\Tests\Unit;

use BluedotBd\SanityCheck\Support\DashboardUrl;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Horizon and Totem can each be moved to their own domain and URI by whoever
 * deploys them. Probing APP_URL instead hits the wrong vhost, gets a 404, and
 * the exposure check reads that as "protected".
 */
class DashboardUrlTest extends TestCase
{
    public static function hosts(): array
    {
        return [
            'bare host' => ['admincore.pro', 'admincore.pro'],
            'https url' => ['https://admincore.pro/', 'admincore.pro'],
            'http url' => ['http://admincore.pro', 'admincore.pro'],
            'upper case' => ['AdminCore.PRO', 'admincore.pro'],
            'custom port' => ['admin.example:8443', 'admin.example:8443'],
            'url with port and path' => ['https://admin.example:8443/totem', 'admin.example:8443'],
            'list takes the first' => ['admincore.pro, admin.example', 'admincore.pro'],
            'list skips empties' => [' , admin.example', 'admin.example'],
            'blank' => ['', null],
            'null' => [null, null],
            'whitespace' => ['   ', null],
        ];
    }

    #[DataProvider('hosts')]
    public function test_normalises_a_configured_host(?string $configured, ?string $expected): void
    {
        $this->assertSame($expected, DashboardUrl::host($configured));
    }

    public function test_uses_the_app_url_when_no_domain_is_configured(): void
    {
        $this->assertSame(
            'https://app.example/horizon',
            DashboardUrl::build('https://app.example', 'horizon')
        );

        $this->assertSame(
            'https://app.example/horizon',
            DashboardUrl::build('https://app.example/', '/horizon')
        );
    }

    public function test_switches_host_but_keeps_the_app_url_scheme(): void
    {
        $this->assertSame(
            'https://admincore.pro/totem',
            DashboardUrl::build('https://app.example', 'totem', 'admincore.pro')
        );

        $this->assertSame(
            'http://admincore.pro/totem',
            DashboardUrl::build('http://app.example', 'totem', 'admincore.pro')
        );
    }

    public function test_honours_a_custom_uri(): void
    {
        $this->assertSame(
            'https://admincore.pro/ops/queue',
            DashboardUrl::build('https://app.example', '/ops/queue/', 'https://admincore.pro/')
        );
    }

    public function test_a_configured_domain_is_used_even_without_an_app_url(): void
    {
        $this->assertSame(
            'https://admincore.pro/totem',
            DashboardUrl::build(null, 'totem', 'admincore.pro')
        );
    }

    public function test_returns_null_without_either_base_url_or_domain(): void
    {
        $this->assertNull(DashboardUrl::build(null, 'totem'));
        $this->assertNull(DashboardUrl::build('', 'totem'));
    }

    public function test_totem_exposure_probes_the_configured_domain_and_uri(): void
    {
        $source = file_get_contents(__DIR__.'/../../src/Checks/TotemExposureCheck.php');

        // The dashboard's own config decides where it lives.
        $this->assertStringContainsString("config('totem.allowed_hosts')", $source);
        $this->assertStringContainsString("config('totem.web.route_prefix'", $source);
    }

    public function test_dashboard_targets_read_the_package_config(): void
    {
        $source = file_get_contents(__DIR__.'/../../src/Checks/DashboardExposureCheck.php');

        $this->assertStringContainsString("config('horizon.domain')", $source);
        $this->assertStringContainsString("config('horizon.path'", $source);
        $this->assertStringContainsString("config('telescope.path'", $source);
    }
}
