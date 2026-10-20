<?php

namespace BluedotBd\SanityCheck\Tests\Unit;

use BluedotBd\SanityCheck\Support\PayloadInspector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class PayloadInspectorTest extends TestCase
{
    private function inspector(): PayloadInspector
    {
        $config = require __DIR__ . '/../../config/sanity-check.php';

        return new PayloadInspector($config['middleware']['patterns'], $config['middleware']['ignored_keys']);
    }

    public static function maliciousPayloads(): array
    {
        return [
            'eval call' => ['eval($_POST["cmd"])', 'php_code_execution'],
            'eval with space' => ['eval ($code)', 'php_code_execution'],
            'exec call' => ['exec("id")', 'php_code_execution'],
            'exec with space' => ['exec ("whoami")', 'php_code_execution'],
            'shell_exec call' => ['shell_exec("ls -la")', 'php_code_execution'],
            'system call' => ['system("cat /etc/hosts")', 'php_code_execution'],
            'passthru call' => ['passthru($_GET["c"])', 'php_code_execution'],
            'proc_open call' => ['proc_open("/bin/sh", [], $p)', 'php_code_execution'],
            'assert call' => ['assert("phpinfo()")', 'php_code_execution'],
            'base64_decode call' => ['base64_decode("ZWNobyAxOw==")', 'php_obfuscation'],
            'gzinflate call' => ['gzinflate($payload)', 'php_obfuscation'],
            'php superglobal' => ['if(isset($_REQUEST["x"])){}', 'php_superglobal'],
            'php opening tag' => ['<?php echo "x"; ?>', 'php_tag'],
            'short echo tag' => ['<?= $x ?>', 'php_tag'],
            'php stream wrapper' => ['php://filter/convert.base64-encode/resource=index.php', 'stream_wrapper'],
            'data stream wrapper' => ['data://text/plain;base64,PD9waHA=', 'stream_wrapper'],
            'backtick command' => ['`whoami`', 'backtick_command'],
            'command substitution' => ['$(whoami)', 'command_substitution'],
            'rm -rf' => ['rm -rf /', 'shell_command'],
            'chmod 777' => ['chmod 777 storage', 'shell_command'],
            'bin sh' => ['/bin/sh -c id', 'shell_command'],
            'passwd file' => ['cat /etc/passwd', 'sensitive_path'],
            'shadow file' => ['head -n1 /etc/shadow', 'sensitive_path'],
        ];
    }

    #[DataProvider('maliciousPayloads')]
    public function test_detects_malicious_payload(string $payload, string $expectedRule): void
    {
        $this->assertSame($expectedRule, $this->inspector()->detect($payload));
    }

    public static function benignPayloads(): array
    {
        return [
            'plain name' => ['5 Lions Megaways'],
            'amount' => ['Amount: 1,000.50'],
            'phone number' => ['01712345678'],
            'email' => ['support@example.com'],
            'sentence' => ['The system is under maintenance tonight.'],
            'word containing' => ['executive summary of deposits'],
            'url' => ['https://www.example.com/game?data=1&php=2'],
            'base64 image' => ['data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=='],
            'markdown backticks' => ['Please update `payment` status manually'],
            'jquery snippet' => ["$('#game').hide()"],
            'multiline notice' => ["Line one\nLine two\nLine three"],
        ];
    }

    #[DataProvider('benignPayloads')]
    public function test_allows_benign_payload(string $payload): void
    {
        $this->assertNull($this->inspector()->detect($payload));
    }

    public function test_reports_nested_offending_field(): void
    {
        $threat = $this->inspector()->findThreat([
            'game' => ['name' => 'Book of Ra', 'note' => 'exec("rm -rf /")'],
        ]);

        $this->assertSame(['field' => 'game.note', 'rule' => 'php_code_execution'], $threat);
    }

    public function test_ignores_password_fields(): void
    {
        $inspector = $this->inspector();

        $this->assertNull($inspector->findThreat(['password' => 'eval(']));
        $this->assertNull($inspector->findThreat(['user' => ['password_confirmation' => 'system(']]));
    }

    public function test_clean_payload_returns_null(): void
    {
        $this->assertNull($this->inspector()->findThreat([
            'title' => 'Weekly report',
            'amount' => 500,
            'note' => 'All good',
        ]));
    }
}