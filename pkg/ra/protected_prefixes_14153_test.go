package ra

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14153: configEqual omitted ProtectedPrefixes, so a day-2 commit that
// only changed the box-wide protected set (a new configured IPv6 subnet)
// left configEqual==true, Apply kept the running sender, and delegated
// PIO filtering used the stale set until an unrelated RA edit or restart.
// These cells pin the comparison at both the unit seam and the Manager
// seam named in the issue's decisive regression check.

func TestConfigEqual_DifferentProtectedPrefixes14153(t *testing.T) {
	mk := func(prot ...string) *config.RAInterfaceConfig {
		return &config.RAInterfaceConfig{
			Interface:         "trust0",
			Prefixes:          []*config.RAPrefix{{Prefix: "2001:db8:1::/64", OnLink: true, Autonomous: true, Delegated: true}},
			ProtectedPrefixes: prot,
		}
	}
	if configEqual(mk("2001:db8:99::/64"), mk("2001:db8:1::/64")) {
		t.Error("different ProtectedPrefixes should not be equal (sender must restart)")
	}
	if configEqual(mk(), mk("2001:db8:1::/64")) {
		t.Error("adding a ProtectedPrefixes entry should not be equal (sender must restart)")
	}
	if configEqual(mk("2001:db8:1::/64"), mk()) {
		t.Error("removing a ProtectedPrefixes entry should not be equal (sender must restart)")
	}
}

// The comparison must be over the effective (parsed, masked, IPv6) set:
// ConfiguredIPv6Prefixes derives order from Go map iteration, so a raw
// or order-sensitive compare would spurious-restart senders (and flap
// the cluster RA digest) on every no-op reconcile of the same config.
func TestConfigEqual_ProtectedPrefixesEffectiveSet14153(t *testing.T) {
	mk := func(prot ...string) *config.RAInterfaceConfig {
		return &config.RAInterfaceConfig{Interface: "trust0", ProtectedPrefixes: prot}
	}
	cases := []struct {
		name string
		a, b []string
	}{
		{"reordered", []string{"2001:db8:1::/64", "2001:db8:2::/64"}, []string{"2001:db8:2::/64", "2001:db8:1::/64"}},
		{"duplicated", []string{"2001:db8:1::/64", "2001:db8:1::/64"}, []string{"2001:db8:1::/64"}},
		{"host bits masked", []string{"2001:db8:1::5/64"}, []string{"2001:db8:1::/64"}},
		{"non-canonical text", []string{"2001:0db8:0001::/64"}, []string{"2001:db8:1::/64"}},
		{"unparseable skipped", []string{"2001:db8:1::/64", "not-a-prefix"}, []string{"2001:db8:1::/64"}},
		{"ipv4 skipped", []string{"2001:db8:1::/64", "192.0.2.0/24"}, []string{"2001:db8:1::/64"}},
		{"4in6 skipped", []string{"2001:db8:1::/64", "::ffff:192.0.2.0/120"}, []string{"2001:db8:1::/64"}},
		{"nil vs empty", nil, []string{}},
	}
	for _, tc := range cases {
		if !configEqual(mk(tc.a...), mk(tc.b...)) {
			t.Errorf("%s: ProtectedPrefixes %v vs %v should be equal (no spurious restart)", tc.name, tc.a, tc.b)
		}
	}
}

// TestManagerApply_ProtectedPrefixesOnlyChangeRestartsSender14153 is the
// issue's decisive check at the Manager seam: Apply, then Apply with only
// ProtectedPrefixes changed to cover the delegated prefix, and assert the
// sender was restarted with the new cfg (old conn closed, new conn live)
// and its buildRA now suppresses the overlapping delegated PIO.
// RED on revert of the configEqual fix: the second Apply is a no-op
// (configEqual==true), the original conn stays live, and the delegated
// prefix is still advertised.
func TestManagerApply_ProtectedPrefixesOnlyChangeRestartsSender14153(t *testing.T) {
	delegated := func(prot ...string) *config.RAInterfaceConfig {
		c := testCfg("lo")
		c.Prefixes = []*config.RAPrefix{
			{Prefix: "2606:4700:1::/64", OnLink: true, Autonomous: true, Delegated: true},
			{Prefix: "2606:4700:2::/64", OnLink: true, Autonomous: true, Delegated: true},
		}
		c.ProtectedPrefixes = prot
		return c
	}
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()

	if err := m.Apply([]*config.RAInterfaceConfig{delegated("2606:4700:99::/64")}); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	firstConn := waitConn(t, fl.getConn, "lo")
	waitWrites(t, firstConn, 1)
	if got := fl.liveCount(); got != 1 {
		t.Fatalf("live conns after initial Apply = %d, want 1", got)
	}

	// Day-2 change: the delegated 2606:4700:1::/64 now overlaps configured
	// space. Nothing else changes.
	if err := m.Apply([]*config.RAInterfaceConfig{delegated("2606:4700:1::/64")}); err != nil {
		t.Fatalf("protected-only Apply: %v", err)
	}
	// The sender must have been restarted: a new conn is live, exactly one
	// conn is live, and the running sender carries the new protected set.
	secondConn := waitConn(t, fl.getConn, "lo")
	if secondConn == firstConn {
		t.Fatal("sender was not restarted on a ProtectedPrefixes-only change; " +
			"the running sender still filters delegated prefixes against the stale set (#14153)")
	}
	waitWrites(t, secondConn, 1)
	if got := fl.liveCount(); got != 1 {
		t.Fatalf("live conns after restart = %d, want 1", got)
	}

	m.mu.Lock()
	running := m.senders["lo"]
	m.mu.Unlock()
	if running == nil {
		t.Fatal("no running sender for lo after protected-only Apply")
	}
	if len(running.cfg.ProtectedPrefixes) != 1 || running.cfg.ProtectedPrefixes[0] != "2606:4700:1::/64" {
		t.Fatalf("running sender ProtectedPrefixes = %v, want [2606:4700:1::/64]", running.cfg.ProtectedPrefixes)
	}

	// And the new sender's wire output suppresses the now-protected
	// delegated prefix while keeping the non-overlapping one.
	pios := rawPrefixInfosForClassTest(t, running.cfg)
	if len(pios) != 1 || pios[0].Prefix.String() != "2606:4700:2::" {
		t.Fatalf("PIOs after restart = %+v, want only the non-overlapping delegated 2606:4700:2::/64", pios)
	}

	_ = m.Clear()
}
