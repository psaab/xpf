package snmp

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestSendLinkTraps_DoesNotBlock is the fail-on-revert guard for #2991. The
// link monitor calls NotifyLinkUp/Down inline; a real trap sender does a
// blocking net.DialTimeout (2s) plus DNS resolution for an FQDN target. We
// inject a deliberately slow sender to model that delay deterministically: with
// async dispatch the caller returns effectively immediately, while a
// synchronous revert (calling trapSender inline in sendLinkTraps) would block
// the caller for the full sender delay × target count. The injected sender is
// the seam the issue asks for ("a unit test with an injected slow trap
// sender").
func TestSendLinkTraps_DoesNotBlock(t *testing.T) {
	const slow = 2 * time.Second
	released := make(chan struct{})
	// #5023: inject the slow sender on THIS Agent (no shared package global,
	// so no race with the running trap worker's read).
	slowSender := func(target string, pkt []byte) error {
		// Block until the test releases us (models a hung dial/DNS).
		<-released
		return nil
	}
	defer close(released)

	agent := &Agent{
		cfg: &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{"public": {Name: "public"}},
			TrapGroups: map[string]*config.SNMPTrapGroup{
				// Many targets: a synchronous loop would multiply the per-send
				// stall by the target count.
				"dead": {Name: "dead", Targets: []string{
					"192.0.2.1:162", "192.0.2.2:162", "192.0.2.3:162",
					"192.0.2.4:162", "192.0.2.5:162",
				}},
			},
		},
		startTime:  time.Now(),
		trapSender: slowSender,
	}

	done := make(chan struct{})
	start := time.Now()
	go func() {
		agent.NotifyLinkDown(7, "ge-0-0-7", true)
		close(done)
	}()

	select {
	case <-done:
		if elapsed := time.Since(start); elapsed >= slow {
			t.Fatalf("NotifyLinkDown took %v (>= slow sender budget): delivery is not async (#2991)", elapsed)
		}
	case <-time.After(slow):
		t.Fatal("NotifyLinkDown blocked the caller on the slow trap sender: trap delivery is not async (#2991)")
	}
}

// TestEnqueueTrap_DropsWhenFull proves the async queue is BOUNDED and drops
// (incrementing the counter) rather than blocking or growing without limit when
// the worker cannot keep up. This guards the bound half of #2991.
func TestEnqueueTrap_DropsWhenFull(t *testing.T) {
	agent := &Agent{startTime: time.Now()}
	// Pre-create a full queue WITHOUT a draining worker so every enqueue past
	// capacity must drop. Mark the once as done so enqueueTrap does not start a
	// worker that would drain it.
	agent.trapQueue = make(chan trapJob, 4)
	agent.trapWorkerOnce.Do(func() {}) // consume the Once so no worker starts

	for i := 0; i < cap(agent.trapQueue); i++ {
		agent.enqueueTrap(trapJob{target: "192.0.2.9:162", pkt: []byte{1}})
	}
	if agent.trapsDropped.Load() != 0 {
		t.Fatalf("dropped before full: %d", agent.trapsDropped.Load())
	}
	for i := 0; i < 10; i++ {
		agent.enqueueTrap(trapJob{target: "192.0.2.9:162", pkt: []byte{1}})
	}
	if got := agent.trapsDropped.Load(); got != 10 {
		t.Fatalf("trapsDropped = %d, want 10 (bounded queue must drop when full)", got)
	}
}

// TestSendLinkTraps_AsyncDelivers confirms async dispatch still delivers to a
// live target (the worker drains the queue and writes the packet).
func TestSendLinkTraps_AsyncDelivers(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	agent := &Agent{
		cfg: &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{"public": {Name: "public"}},
			TrapGroups: map[string]*config.SNMPTrapGroup{
				"live": {Name: "live", Targets: []string{pc.LocalAddr().String()}},
			},
		},
		startTime: time.Now(),
	}

	agent.NotifyLinkUp(2, "ge-0-0-2", true)

	buf := make([]byte, 4096)
	pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read async trap: %v", err)
	}
	if n == 0 {
		t.Fatal("empty async trap")
	}
}
