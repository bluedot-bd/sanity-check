<?php

namespace BluedotBd\SanityCheck\Tests\Unit;

use BluedotBd\SanityCheck\Support\NodePackages;
use BluedotBd\SanityCheck\Support\NpmAdvisoryClient;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class NpmAdvisoryTest extends TestCase
{
    public static function specs(): array
    {
        return [
            'caret' => ['^1.2.3', '1.2.3'],
            'tilde' => ['~2.0', '2.0.0'],
            'exact' => ['4.17.21', '4.17.21'],
            'range' => ['>=1.0.0 <2.0.0', '1.0.0'],
            'star' => ['*', null],
            'latest' => ['latest', null],
            'workspace' => ['workspace:*', null],
            'git' => ['git+https://github.com/x/y.git', null],
            'file' => ['file:../shared', null],
            'npm alias' => ['npm:other@1.2.3', null],
        ];
    }

    #[DataProvider('specs')]
    public function test_turns_ranges_into_a_concrete_version(string $spec, ?string $expected): void
    {
        $this->assertSame($expected, NodePackages::lowestVersion($spec));
    }

    public function test_reads_package_json_and_skips_non_registry_specs(): void
    {
        $json = json_encode([
            'dependencies' => [
                'lodash' => '^4.17.20',
                'axios' => '^1.6.4',
                'local' => 'file:../local',
            ],
            'devDependencies' => [
                'vite' => '~5.4.0',
            ],
            'optionalDependencies' => [
                'fsevents' => '^2.3.3',
            ],
        ]);

        $all = NodePackages::fromPackageJson((string) $json);
        $prod = NodePackages::fromPackageJson((string) $json, false);

        $this->assertSame(
            ['axios' => '1.6.4', 'fsevents' => '2.3.3', 'lodash' => '4.17.20', 'vite' => '5.4.0'],
            $all
        );
        $this->assertSame(
            ['axios' => '1.6.4', 'fsevents' => '2.3.3', 'lodash' => '4.17.20'],
            $prod
        );
    }

    public function test_reads_lockfile_v3_packages_map(): void
    {
        $json = json_encode([
            'lockfileVersion' => 3,
            'packages' => [
                '' => ['name' => 'app'],
                'node_modules/lodash' => ['version' => '4.17.20'],
                'node_modules/@scope/pkg' => ['version' => '1.0.0'],
                'node_modules/a/node_modules/nested' => ['version' => '2.1.0'],
                'node_modules/vite' => ['version' => '5.4.0', 'dev' => true],
            ],
        ]);

        $this->assertSame(
            ['@scope/pkg' => '1.0.0', 'lodash' => '4.17.20', 'nested' => '2.1.0', 'vite' => '5.4.0'],
            NodePackages::fromLockJson((string) $json)
        );

        $this->assertSame(
            ['@scope/pkg' => '1.0.0', 'lodash' => '4.17.20', 'nested' => '2.1.0'],
            NodePackages::fromLockJson((string) $json, false)
        );
    }

    public function test_reads_lockfile_v1_dependency_tree(): void
    {
        $json = json_encode([
            'lockfileVersion' => 1,
            'dependencies' => [
                'lodash' => [
                    'version' => '4.17.20',
                    'dependencies' => [
                        'nested' => ['version' => '1.0.1'],
                    ],
                ],
                'vite' => ['version' => '5.4.0', 'dev' => true],
            ],
        ]);

        $this->assertSame(
            ['lodash' => '4.17.20', 'nested' => '1.0.1', 'vite' => '5.4.0'],
            NodePackages::fromLockJson((string) $json)
        );

        $this->assertSame(
            ['lodash' => '4.17.20', 'nested' => '1.0.1'],
            NodePackages::fromLockJson((string) $json, false)
        );
    }

    public function test_ignores_invalid_json(): void
    {
        $this->assertSame([], NodePackages::fromPackageJson('{not json'));
        $this->assertSame([], NodePackages::fromLockJson(''));
    }

    public static function npmRanges(): array
    {
        return [
            'below' => ['4.17.20', '<4.17.21', true],
            'at fix' => ['4.17.21', '<4.17.21', false],
            'and range' => ['1.2.3', '>=1.0.0 <1.3.0', true],
            'or range' => ['2.5.0', '^2.0.0 || ^3.0.0', true],
            'hyphen range' => ['1.5.0', '1.0.0 - 2.0.0', true],
            'outside' => ['3.0.0', '<2.0.0', false],
            'empty' => ['1.0.0', '', false],
        ];
    }

    #[DataProvider('npmRanges')]
    public function test_matches_npm_version_ranges(string $version, string $range, bool $expected): void
    {
        $this->assertSame($expected, NpmAdvisoryClient::isVulnerable($version, $range));
    }

    public function test_filters_and_sorts_advisories(): void
    {
        $response = [
            'lodash' => [
                [
                    'id' => 1106913,
                    'title' => 'Command Injection in lodash',
                    'severity' => 'high',
                    'vulnerable_versions' => '<4.17.21',
                    'url' => 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
                    'cwe' => ['CWE-77'],
                ],
                [
                    'id' => 999,
                    'title' => 'Old issue',
                    'severity' => 'critical',
                    'vulnerable_versions' => '<4.0.0',
                ],
                [
                    'id' => 111,
                    'title' => 'Ignored on purpose',
                    'severity' => 'low',
                    'vulnerable_versions' => '*',
                ],
            ],
            'not-installed' => [
                ['id' => 1, 'title' => 'Nope', 'severity' => 'critical', 'vulnerable_versions' => '*'],
            ],
        ];

        $findings = NpmAdvisoryClient::filter($response, ['lodash' => '4.17.20'], ['111']);

        $this->assertCount(1, $findings);
        $this->assertSame('1106913', $findings[0]['advisory_id']);
        $this->assertSame('high', $findings[0]['severity']);
        $this->assertSame('<4.17.21', $findings[0]['vulnerable']);
        $this->assertSame('CWE-77', $findings[0]['cwe']);
    }

    public function test_severity_filter_and_ordering(): void
    {
        $response = [
            'pkg' => [
                ['id' => 1, 'title' => 'low one', 'severity' => 'low', 'vulnerable_versions' => '*'],
                ['id' => 2, 'title' => 'critical one', 'severity' => 'critical', 'vulnerable_versions' => '*'],
                ['id' => 3, 'title' => 'moderate one', 'severity' => 'moderate', 'vulnerable_versions' => '*'],
            ],
        ];

        $findings = NpmAdvisoryClient::filter($response, ['pkg' => '1.0.0'], [], ['critical', 'high', 'moderate']);

        $this->assertSame(['2', '3'], array_column($findings, 'advisory_id'));
        $this->assertSame([0, 2], array_map(fn ($f) => NpmAdvisoryClient::severityRank($f['severity']), $findings));
    }
}