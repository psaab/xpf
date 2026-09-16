package config

import (
	"strings"
	"testing"
)

// #7361: a `pool-utilization-alarm` configured on an ADDRESS-ONLY pool
// (`port no-translation`) measures only a partial signal, and nothing said
// so. Narrowed by #9896: the tracked-flow leg DOES fire for this class, so
// the advisory no longer claims the alarm can never fire — it claims the
// ports leg is dead and collision exhaustion is silent.
//
// `used_ports` is a popcount over the allocator's occupancy bitmaps;
// `reserve_address_only` never touches occupancy — it records ownership in
// `live.address_only_owners`. So the ports leg of the utilization percentage
// is permanently 0.
//
// THE HARM IS NOT THE MISSING PERCENTAGE. The configuration reads as working:
// `show` renders the alarm, and 0% is indistinguishable from a healthy pool.
// The alarm's silence looks exactly like the silence of a pool with headroom.
//
// The issue proposes capacity = AddressCount instead. That models an exhaustion
// mode this pool class does not have — addresses are round-robin and freely
// REUSED across flows with different destination tuples, so the pool exhausts
// on reverse-identity collision. A one-address pool would report 100% after its
// first flow and stay there while serving thousands more: an alarm that fires
// on the first packet and never clears, which is worse than silence because it
// trains operators to ignore the alarm that DOES work elsewhere.

func warnFor7361(t *testing.T, lines ...string) []string {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return natPoolAlarmInapplicableWarnings(cfg)
}

func addrOnlyPool7361(pool string) []string {
	return []string{
		"set security nat source pool " + pool + " address 203.0.113.10",
		"set security nat source pool " + pool + " port no-translation",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		"set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs rule r1 then source-nat pool " + pool,
		"set security nat source pool-utilization-alarm raise-threshold 90",
	}
}

func TestAddressOnlyPoolAlarmWarns7361(t *testing.T) {
	w := warnFor7361(t, addrOnlyPool7361("p1")...)
	if len(w) != 1 {
		t.Fatalf("expected exactly one advisory, got %d: %v", len(w), w)
	}
	for _, want := range []string{`"p1"`, "port no-translation", "tracked-flow", "90"} {
		if !strings.Contains(w[0], want) {
			t.Errorf("the advisory does not mention %q: %s", want, w[0])
		}
	}
}

// THE CONTROL that stops this becoming "warn on every pool". A PORT-BEARING
// pool's alarm works, and warning about it would be the false-alarm noise the
// whole issue is about avoiding.
func TestPortBearingPoolDoesNotWarn7361(t *testing.T) {
	w := warnFor7361(t,
		"set security nat source pool p2 address 203.0.113.20",
		"set security nat source pool p2 port range 1024 65535",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		"set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs rule r1 then source-nat pool p2",
		"set security nat source pool-utilization-alarm raise-threshold 90",
	)
	if len(w) != 0 {
		t.Errorf("a port-bearing pool was flagged; its alarm measures correctly: %v", w)
	}
}

// NO ALARM CONFIGURED means nothing claims to fire, so there is nothing to warn
// about. Without this, the advisory fires on every address-only pool in every
// config and becomes noise an operator learns to skip.
func TestNoAlarmConfiguredDoesNotWarn7361(t *testing.T) {
	lines := addrOnlyPool7361("p3")
	lines = lines[:len(lines)-1] // drop the raise-threshold
	if w := warnFor7361(t, lines...); len(w) != 0 {
		t.Errorf("warned with no alarm configured: %v", w)
	}
}

// AN UNREFERENCED POOL is not monitored at all, so warning about it would
// report an alarm that was never going to be evaluated — for a different
// reason than this issue's.
func TestUnreferencedPoolDoesNotWarn7361(t *testing.T) {
	w := warnFor7361(t,
		"set security nat source pool orphan address 203.0.113.30",
		"set security nat source pool orphan port no-translation",
		"set security nat source pool-utilization-alarm raise-threshold 90",
	)
	if len(w) != 0 {
		t.Errorf("warned about an unreferenced pool: %v", w)
	}
}

// The advisory must reach ValidateConfig, not merely exist. A helper nobody
// calls is the shape of defect this campaign keeps finding.
func TestAdvisoryReachesValidateConfig7361(t *testing.T) {
	tree := &ConfigTree{}
	for _, l := range addrOnlyPool7361("p4") {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	var found bool
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "tracked-flow") && strings.Contains(w, `"p4"`) {
			found = true
		}
	}
	if !found {
		t.Error("the #7361 advisory is not emitted by ValidateConfig; the operator " +
			"never sees it, which is the entire point of the change")
	}
}

// DETERMINISTIC pools measure only a partial signal (#9902 F-026, narrowed by
// the #9896 fold 2): the ports leg is excluded — aggregate utilization cannot
// predict per-block exhaustion — while the tracked-flow leg fires for this
// class. They get their OWN sentence — never the address-only one, even when
// the pool is ALSO address-only (the block structure, not the port mode, is
// the operative cause). Silence about a threshold that fires only partially
// is the harm #7361 exists to end, and it applies to this class identically.
func TestDeterministicPoolFlagged9902(t *testing.T) {
	w := warnFor7361(t,
		"set security nat source pool det address 203.0.113.40",
		"set security nat source pool det port no-translation",
		"set security nat source pool det address-persistent",
		// The deterministic config lives under `port deterministic ...`, not a
		// bare `deterministic`. The first version of this fixture used the bare
		// path, never set pool.Deterministic, and so asserted the skip against a
		// pool that was not deterministic at all — it failed loudly, which is
		// the good direction, but it is the same class as any fixture that does
		// not reach the condition it names.
		"set security nat source pool det port deterministic block-size 64",
		"set security nat source pool det port deterministic host address 10.0.0.0/28",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		"set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs rule r1 then source-nat pool det",
		"set security nat source pool-utilization-alarm raise-threshold 90",
	)
	var flagged []string
	for _, x := range w {
		if strings.Contains(x, `"det"`) {
			flagged = append(flagged, x)
		}
	}
	if len(flagged) != 1 {
		t.Fatalf("expected exactly one advisory for the deterministic pool, got %d: %v", len(flagged), w)
	}
	if !strings.Contains(flagged[0], "cannot predict per-block exhaustion") {
		t.Errorf("deterministic pool must get the deterministic sentence, got: %s", flagged[0])
	}
	if strings.Contains(flagged[0], "no-translation") {
		t.Errorf("deterministic+address-only pool must not get the address-only sentence, got: %s", flagged[0])
	}
}

// A deterministic PORT-BEARING pool is the class the old filter could never
// reach (the `!PortNoTranslation` gate dropped it before the deterministic
// skip): it must warn with the deterministic sentence.
func TestDeterministicPortBearingPoolWarns9902(t *testing.T) {
	w := warnFor7361(t,
		"set security nat source pool detpb address 203.0.113.41",
		"set security nat source pool detpb port range 1024 65535",
		"set security nat source pool detpb port deterministic block-size 64",
		"set security nat source pool detpb port deterministic host address 10.0.0.0/28",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		"set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs rule r1 then source-nat pool detpb",
		"set security nat source pool-utilization-alarm raise-threshold 90",
	)
	if len(w) != 1 {
		t.Fatalf("expected exactly one advisory, got %d: %v", len(w), w)
	}
	if !strings.Contains(w[0], `"detpb"`) || !strings.Contains(w[0], "cannot predict per-block exhaustion") {
		t.Errorf("deterministic port-bearing pool must get the deterministic sentence, got: %s", w[0])
	}
}

// AN ALARM WITH NO RAISE-THRESHOLD claims nothing, so there is nothing to warn
// about — distinct from "no alarm configured at all", which the earlier cell
// covers by a different code path (the nil check, not the threshold gate).
//
// Found by mutation: deleting the threshold gate escaped every other cell,
// because the only fixture without a raise-threshold had no alarm stanza at all
// and returned at the nil check one line earlier. Measured that this state is
// reachable — `clear-threshold 50` with no raise compiles leniently to
// RaiseThreshold: 0 — before writing the assertion.
func TestAlarmWithoutRaiseThresholdDoesNotWarn7361(t *testing.T) {
	w := warnFor7361(t,
		"set security nat source pool p5 address 203.0.113.50",
		"set security nat source pool p5 port no-translation",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		"set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs rule r1 then source-nat pool p5",
		"set security nat source pool-utilization-alarm clear-threshold 50",
	)
	if len(w) != 0 {
		t.Errorf("warned about an alarm with no raise-threshold: %v.\nThe advisory "+
			"says a configured threshold can never fire; with no threshold "+
			"configured, nothing claims to fire and the sentence would be false", w)
	}
}
