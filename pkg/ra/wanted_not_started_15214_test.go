package ra

import (
	"net"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// missingRAInterface15214 is chosen so net.InterfaceByName fails in every
// environment (no host has this name); 17 chars with hyphens is a name no
// kernel netdev can carry.
const missingRAInterface15214 = "xpf-missing-15214"

// TestWantedNotStartedVisibleToDeadSenderProbe15214 is the #15214 acceptance
// probe: an Apply whose netdev is ABSENT at startLocked time inserts no
// sender, so the pre-fix HasDeadSenders walk over m.senders saw nothing, the
// standalone 30s retry owner never fired, and Status reported no entry at
// all. After the fix the wanted-but-not-started interface must be visible to
// both the probe and Status, and removing / withdrawing the config must
// retire it (otherwise the probe would re-drive Apply forever).
func TestWantedNotStartedVisibleToDeadSenderProbe15214(t *testing.T) {
	if _, err := net.InterfaceByName(missingRAInterface15214); err == nil {
		t.Skip("host unexpectedly has the missing-interface name")
	}
	m := New()
	cfg := testCfg(missingRAInterface15214)
	if err := m.Apply([]*config.RAInterfaceConfig{cfg}); err == nil {
		t.Fatal("Apply with a missing netdev returned nil; want the start error")
	}
	if !m.HasDeadSenders() {
		t.Fatal("HasDeadSenders() = false for a wanted interface whose netdev was absent at Apply — " +
			"the #6793 retry owner never fires and the LAN gets no RAs until an unrelated commit (#15214)")
	}
	if got := m.DeadSenderInterfaces(); len(got) != 1 || got[0] != missingRAInterface15214 {
		t.Fatalf("DeadSenderInterfaces() = %v, want [%s]", got, missingRAInterface15214)
	}
	st := m.Status()
	if len(st) != 1 || st[0].Interface != missingRAInterface15214 || st[0].State == "active" {
		t.Fatalf("Status() = %+v, want one non-active entry for the missing interface", st)
	}

	// Control: a Withdraw (operator removed RA) must retire the marker.
	if err := m.Withdraw(); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if m.HasDeadSenders() {
		t.Fatal("HasDeadSenders() = true after Withdraw of the missing interface — stale wanted marker")
	}
	if got := m.Status(); len(got) != 0 {
		t.Fatalf("Status() after Withdraw = %+v, want empty", got)
	}

	// Removing the interface from the desired set (empty Apply) must also
	// retire it.
	if err := m.Apply([]*config.RAInterfaceConfig{cfg}); err == nil {
		t.Fatal("re-Apply with a missing netdev returned nil")
	}
	if !m.HasDeadSenders() {
		t.Fatal("HasDeadSenders() = false after re-Apply of the missing interface")
	}
	if err := m.Apply(nil); err != nil {
		t.Fatalf("empty Apply: %v", err)
	}
	if m.HasDeadSenders() {
		t.Fatal("HasDeadSenders() = true after the interface left the desired set")
	}
}

// TestRepeatedENODEVSendFailureMarksSenderDead15214: a sender whose conn
// opened but whose every RA write fails with ENODEV (netdev deleted outside
// a commit) must become visible to the same probe after repeated failures,
// instead of staying "active" while silently sending nothing.
func TestRepeatedENODEVSendFailureMarksSenderDead15214(t *testing.T) {
	requireLo(t)
	getConn, _ := installFakeListen(t)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fc := waitConn(t, getConn, "lo")
	waitWrites(t, fc, 1)
	// Further writes fail as if the netdev vanished.
	fc.setWriteErr(syscall.ENODEV)

	m.mu.Lock()
	s := m.senders["lo"]
	m.mu.Unlock()
	if s == nil {
		t.Fatal("no sender for lo")
	}
	// Well above any sane consecutive-failure threshold.
	for range 5 {
		s.sendRA()
	}
	if !m.HasDeadSenders() {
		t.Fatal("HasDeadSenders() = false after repeated ENODEV send failures — " +
			"the sender stays 'active' and the retry owner never rebuilds it (#15214)")
	}
	st := m.Status()
	if len(st) != 1 || st[0].State == "active" {
		t.Fatalf("Status() = %+v, want a non-active entry after ENODEV send death", st)
	}
	_ = m.Clear()
}

// TestHealthySenderNotDead15214 is the adjacent control for the two legs
// above: a sender whose conn opened and whose writes succeed stays not-dead
// and reports State "active".
func TestHealthySenderNotDead15214(t *testing.T) {
	requireLo(t)
	installFakeListen(t)
	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	m.mu.Lock()
	s := m.senders["lo"]
	m.mu.Unlock()
	if s == nil {
		t.Fatal("no sender for lo")
	}
	if !s.waitConnReady(claimWaitTimeout) {
		t.Fatal("healthy fake sender never signalled conn ready")
	}
	s.sendRA()
	if m.HasDeadSenders() {
		t.Fatal("HasDeadSenders() = true for a healthy sender — the 30s loop would restart it forever")
	}
	st := m.Status()
	if len(st) != 1 || st[0].State != "active" {
		t.Fatalf("Status() = %+v, want one active entry", st)
	}
	_ = m.Clear()
}
