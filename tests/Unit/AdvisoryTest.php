<?php

namespace BluedotBd\SanityCheck\Tests\Unit;

use BluedotBd\SanityCheck\Support\AdvisoryClient;
use BluedotBd\SanityCheck\Support\InstalledPackages;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class AdvisoryTest extends TestCase
{
    public static function affectedVersions(): array
    {
        return [
            'inside range' => ['1.2.3', '>=1.0.0,<1.5.0', true],
            'at upper bound' => ['1.5.0', '>=1.0.0,<1.5.0', false],
            'below range' => ['0.9.9', '>=1.0.0,<1.5.0', false],
            'normalized version' => ['1.2.3.0', '>=1.0,<1.5', true],
            'wildcard' => ['2.4.1', '2.*', true],
            'other major' => ['3.0.0', '2.*', false],
            'empty constraint' => ['1.0.0', '', false],
            'dev version' => ['dev-main', '>=1.0', false],
            'text version' => ['v1.2.3', '>=1.0.0,<1.5.0', true],
        ];
    }

    #[DataProvider('affectedVersions')]
    public function test_knows_whether_a_version_is_affected(string $version, string $constraint, bool $expected): void
    {
        $this->assertSame($expected, AdvisoryClient::isAffected($version, $constraint));
    }

    public function test_filters_api_response_by_installed_version(): void
    {
        $response = [
            'vendor/package' => [
                [
                    'advisoryId' => 'PKSA-aaaa-bbbb-cccc',
                    'packageName' => 'vendor/package',
                    'affectedVersions' => '>=1.0.0,<2.0.0',
                    'title' => 'Remote code execution',
                    'cve' => 'CVE-2026-0001',
                    'link' => 'https://example.com/advisory',
                    'sources' => [['name' => 'GitHub', 'remoteId' => 'GHSA-xxxx']],
                ],
                [
                    'advisoryId' => 'PKSA-old-old-old',
                    'affectedVersions' => '>=0.1.0,<0.5.0',
                    'title' => 'Old issue',
                ],
            ],
            'other/package' => [
                ['advisoryId' => 'PKSA-not-installed', 'affectedVersions' => '*', 'title' => 'Not installed'],
            ],
        ];

        $findings = AdvisoryClient::filter($response, ['vendor/package' => '1.4.2.0']);

        $this->assertCount(1, $findings);
        $this->assertSame('vendor/package', $findings[0]['package']);
        $this->assertSame('PKSA-aaaa-bbbb-cccc', $findings[0]['advisory_id']);
        $this->assertSame('CVE-2026-0001', $findings[0]['cve']);
        $this->assertSame('>=1.0.0,<2.0.0', $findings[0]['affected']);
    }

    public function test_ignores_configured_advisory_ids(): void
    {
        $response = [
            'vendor/package' => [
                ['advisoryId' => 'PKSA-ignore-me', 'affectedVersions' => '*', 'title' => 'Known risk'],
            ],
        ];

        $this->assertSame([], AdvisoryClient::filter($response, ['vendor/package' => '1.0.0'], ['PKSA-ignore-me']));
    }

    public function test_reads_composer_installed_json(): void
    {
        $json = json_encode([
            'packages' => [
                ['name' => 'vendor/package', 'version' => 'v1.2.3', 'version_normalized' => '1.2.3.0'],
                ['name' => 'vendor/dev-only', 'version' => 'v2.0.0', 'dev_requirement' => true],
            ],
        ]);

        $all = InstalledPackages::fromInstalledJson((string) $json);
        $prod = InstalledPackages::fromInstalledJson((string) $json, false);

        $this->assertSame(['vendor/dev-only' => 'v2.0.0', 'vendor/package' => '1.2.3.0'], $all);
        $this->assertSame(['vendor/package' => '1.2.3.0'], $prod);
    }

    public function test_reads_composer_lock(): void
    {
        $json = json_encode([
            'packages' => [
                ['name' => 'vendor/package', 'version' => 'v1.0.0'],
            ],
            'packages-dev' => [
                ['name' => 'phpunit/phpunit', 'version' => '11.5.0'],
            ],
        ]);

        $this->assertSame(
            ['phpunit/phpunit' => '11.5.0', 'vendor/package' => 'v1.0.0'],
            InstalledPackages::fromLockJson((string) $json)
        );

        $this->assertSame(['vendor/package' => 'v1.0.0'], InstalledPackages::fromLockJson((string) $json, false));
    }

    public function test_ignores_invalid_json(): void
    {
        $this->assertSame([], InstalledPackages::fromInstalledJson('{not json'));
        $this->assertSame([], InstalledPackages::fromLockJson(''));
    }
}