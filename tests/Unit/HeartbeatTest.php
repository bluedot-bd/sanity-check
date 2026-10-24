<?php

namespace BluedotBd\SanityCheck\Tests\Unit;

use BluedotBd\SanityCheck\Notifications\Notifier;
use BluedotBd\SanityCheck\Report;
use BluedotBd\SanityCheck\Results\Result;
use Illuminate\Contracts\Container\Container;
use PHPUnit\Framework\TestCase;

class HeartbeatTest extends TestCase
{
    /**
     * @param  array<string, mixed>  $notifications
     */
    private function notifier(array $notifications): Notifier
    {
        return new Notifier($this->createStub(Container::class), $notifications);
    }

    private function cleanReport(): Report
    {
        return new Report([
            Result::pass('advisories', 'Security advisories', 'No advisory affects the 42 installed packages.'),
        ]);
    }

    public function test_a_clean_run_is_announced_only_when_the_heartbeat_is_on(): void
    {
        $report = $this->cleanReport();

        $this->assertFalse(
            $this->notifier(['enabled' => true, 'heartbeat' => ['enabled' => false]])->shouldSendHeartbeat($report)
        );

        $this->assertTrue(
            $this->notifier(['enabled' => true, 'heartbeat' => ['enabled' => true]])->shouldSendHeartbeat($report)
        );
    }

    public function test_the_heartbeat_respects_the_master_switch(): void
    {
        $this->assertFalse(
            $this->notifier(['enabled' => false, 'heartbeat' => ['enabled' => true]])
                ->shouldSendHeartbeat($this->cleanReport())
        );
    }

    public function test_a_run_with_findings_never_sends_a_heartbeat(): void
    {
        $notifier = $this->notifier(['enabled' => true, 'heartbeat' => ['enabled' => true]]);

        $failed = new Report([Result::fail('advisories.vendor/pkg', 'vendor/pkg 1.0.0', 'PKSA-1: bad')]);
        $warned = new Report([Result::warn('advisories.lookup', 'Advisory lookup', 'lookup timed out')]);

        $this->assertFalse($notifier->shouldSendHeartbeat($failed));
        $this->assertFalse($notifier->shouldSendHeartbeat($warned));
    }

    public function test_send_heartbeat_is_a_no_op_when_disabled(): void
    {
        $notifier = $this->notifier(['enabled' => true, 'heartbeat' => ['enabled' => false]]);

        $this->assertSame([], $notifier->sendHeartbeat($this->cleanReport()));
    }

    public function test_is_clean_ignores_passing_results(): void
    {
        $this->assertTrue((new Report([]))->isClean());
        $this->assertTrue((new Report([Result::pass('a', 'A', 'ok')]))->isClean());
        $this->assertFalse((new Report([Result::warn('a', 'A', 'hm')]))->isClean());
        $this->assertFalse((new Report([Result::fail('a', 'A', 'no')]))->isClean());
    }
}
