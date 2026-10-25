package config

import (
	"strings"
	"testing"
)

// TestRPMRoutingInstanceStrictRejects pins the #2496 commit-time gate: an
// RPM test whose `routing-instance` names a nonexistent / typo'd instance
// is hard-rejected on the strict path (commit / commit-check). The runtime
// would bind the probe DATA socket to a synthesized vrf-<name> device
// (SO_BINDTODEVICE) that does not exist -> ENODEV -> the probe never sends
// a packet and the test silently HOLDS its state forever, starving any
// event-options / ip-monitoring policy keyed off it of a failover signal.
//
// The target is an IP literal so the scoped-hostname gate (#2493), which
// runs earlier and would also reject a hostname on a scoped test, does not
// fire first — this isolates the routing-instance cross-reference check.
//
// This FAILS against master, which has no routing-instance cross-reference
// gate and silently accepts the unprobeable test.
func TestRPMRoutingInstanceStrictRejects(t *testing.T) {
	lines := []string{
		"set routing-instances ISP-B instance-type forwarding",
		"set services rpm probe P test t routing-instance ISP-TYPO",
		"set services rpm probe P test t target 8.8.8.8",
	}
	tree := buildTree(t, lines)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an RPM test referencing a nonexistent routing-instance; want strict reject")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err = %v, want substring %q", err, "does not exist")
	}
}

// TestRPMRoutingInstanceLenientWarns pins the no-brick contract (#1960
// doctrine): the nonexistent-instance the strict path rejects is TOLERATED
// on the lenient load / peer-sync path — downgraded to a warning so an
// already-persisted or peer-synced config still boots. The runtime VRF
// bind then returns ENODEV and the test holds state.
func TestRPMRoutingInstanceLenientWarns(t *testing.T) {
	lines := []string{
		"set routing-instances ISP-B instance-type forwarding",
		"set services rpm probe P test t routing-instance ISP-TYPO",
		"set services rpm probe P test t target 8.8.8.8",
	}
	tree := buildTree(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on a bad rpm routing-instance (brick-on-restart): %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "rpm routing-instance") {
		t.Fatalf("expected a downgraded rpm routing-instance warning, warnings=%v", cfg.Warnings)
	}
}

// TestRPMRoutingInstanceConfiguredAccepted confirms NO regression: an RPM
// test whose routing-instance names a CONFIGURED VRF instance is accepted,
// and a test with an EMPTY routing-instance (default/master context — not
// scoped to any VRF device) is likewise accepted. The virtual-router twin
// is the #16629 positive control: it has a real vrf-<name> device, unlike
// a forwarding instance.
func TestRPMRoutingInstanceConfiguredAccepted(t *testing.T) {
	t.Run("configured virtual-router instance accepted", func(t *testing.T) {
		lines := []string{
			"set routing-instances ISP-B instance-type virtual-router",
			"set services rpm probe P test t routing-instance ISP-B",
			"set services rpm probe P test t target 8.8.8.8",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("RPM test naming a configured virtual-router instance must be accepted: %v", err)
		}
	})

	t.Run("configured vrf instance accepted", func(t *testing.T) {
		lines := []string{
			"set routing-instances ISP-B instance-type vrf",
			"set services rpm probe P test t routing-instance ISP-B",
			"set services rpm probe P test t target 8.8.8.8",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("RPM test naming a configured vrf instance must be accepted: %v", err)
		}
	})

	t.Run("configured omitted-type instance accepted", func(t *testing.T) {
		lines := []string{
			"set routing-instances ISP-B interface ge-0/0/1.0",
			"set services rpm probe P test t routing-instance ISP-B",
			"set services rpm probe P test t target 8.8.8.8",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("RPM test naming a configured omitted-type instance must be accepted: %v", err)
		}
	})

	t.Run("forwarding instance with destination-interface accepted", func(t *testing.T) {
		lines := []string{
			"set routing-instances ISP-B instance-type forwarding",
			"set services rpm probe P test t routing-instance ISP-B",
			"set services rpm probe P test t destination-interface ge-0/0/1",
			"set services rpm probe P test t target 8.8.8.8",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("RPM test naming a forwarding instance but pinned by destination-interface must be accepted (probeOpts binds the egress device, never vrf-<ri>): %v", err)
		}
	})

	t.Run("empty routing-instance (default context) accepted", func(t *testing.T) {
		lines := []string{
			"set services rpm probe P test t target 8.8.8.8",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("RPM test with no routing-instance (default context) must be accepted: %v", err)
		}
	})
}

// TestRPMRoutingInstanceForwardingStrictRejects16629 pins the #16629
// extension of the #2496 gate: an RPM test whose routing-instance names a
// FORWARDING instance is hard-rejected on the strict path. The instance
// exists, so the #2496 existence check passed it — but the daemon creates
// no VRF device for a forwarding instance, so the runtime would bind the
// probe socket to a nonexistent vrf-<name> device and hold unknown with
// zero probes sent forever, starving ip-monitoring of a failover signal.
//
// RED pre-fix: CompileConfig accepted this shape (the old
// TestRPMRoutingInstanceConfiguredAccepted pinned it as accepted).
func TestRPMRoutingInstanceForwardingStrictRejects16629(t *testing.T) {
	lines := []string{
		"set routing-instances ISP-B instance-type forwarding",
		"set services rpm probe P test t routing-instance ISP-B",
		"set services rpm probe P test t target 8.8.8.8",
	}
	tree := buildTree(t, lines)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an RPM test scoped to a forwarding instance (no VRF device); want strict reject (#16629)")
	}
	for _, want := range []string{"ISP-B", "forwarding instance", "no VRF device"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %v, want substring %q", err, want)
		}
	}
}

// TestRPMRoutingInstanceForwardingLenientWarns16629 pins the no-brick
// contract for the forwarding cell: the strict rejection is downgraded to
// a warning on the lenient load / peer-sync path so an already-persisted
// or peer-synced config still boots; the runtime bind returns ENODEV and
// the test holds state.
func TestRPMRoutingInstanceForwardingLenientWarns16629(t *testing.T) {
	lines := []string{
		"set routing-instances ISP-B instance-type forwarding",
		"set services rpm probe P test t routing-instance ISP-B",
		"set services rpm probe P test t target 8.8.8.8",
	}
	tree := buildTree(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on a forwarding rpm routing-instance (brick-on-restart): %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "rpm routing-instance") {
		t.Fatalf("expected a downgraded rpm routing-instance warning, warnings=%v", cfg.Warnings)
	}
	if !hasWarningSubstr(cfg.Warnings, "forwarding instance") {
		t.Fatalf("expected the warning to name the forwarding instance type, warnings=%v", cfg.Warnings)
	}
}
