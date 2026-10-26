package config

import (
	"testing"
)

// compileHB167 is a small helper: parse flat `set` lines with ParseSetCommand
// + SetPath (NEVER NewParser — it merges newlines) and compile.
func compileHB167(t *testing.T, lines []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	return cfg
}

// compileHB167Lenient is the tolerant-path twin for fixtures that deliberately
// carry a dangling class-of-service interface reference, which #7337 made a
// hard commit error. See cosINetTree7080Lenient for why the shared strict
// helper is not loosened instead.
func compileHB167Lenient(t *testing.T, lines []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile error (lenient): %v", err)
	}
	return cfg
}

// TestCompileCoSTrafficControlProfileShapesUnit is the fable-167 F-2
// make-or-break: a traffic-control-profile bound to a unit via
// output-traffic-control-profile must ACTUALLY shape — its shaping-rate and
// scheduler-map fold into the per-unit shaper. RED on revert: before modeling,
// output-traffic-control-profile was silently dropped (SchemaValidate ignores
// unknown keywords, no compiler read it) → ShapingRateBytes==0, no shaping.
func TestCompileCoSTrafficControlProfileShapesUnit(t *testing.T) {
	cfg := compileHB167(t, []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service schedulers be-sched transmit-rate 5g",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler be-sched",
		"set class-of-service traffic-control-profiles wan-tcp shaping-rate 9g",
		"set class-of-service traffic-control-profiles wan-tcp scheduler-map edge-map",
		"set class-of-service traffic-control-profiles wan-tcp guaranteed-rate 2g",
		"set class-of-service traffic-control-profiles wan-tcp delay-buffer-rate 1g",
		"set class-of-service interfaces ge-0/0/2 unit 80 output-traffic-control-profile wan-tcp",
		"set system dataplane-type userspace",
	})

	tcp := cfg.ClassOfService.TrafficControlProfiles["wan-tcp"]
	if tcp == nil {
		t.Fatal("expected traffic-control-profile wan-tcp to be modeled")
	}
	if got, want := tcp.ShapingRateBytes, parseBandwidthLimit("9g"); got != want {
		t.Fatalf("tcp shaping-rate = %d, want %d", got, want)
	}
	if got, want := tcp.GuaranteedRateBytes, parseBandwidthLimit("2g"); got != want {
		t.Fatalf("tcp guaranteed-rate = %d, want %d", got, want)
	}
	if got, want := tcp.DelayBufferRateBytes, parseBandwidthLimit("1g"); got != want {
		t.Fatalf("tcp delay-buffer-rate = %d, want %d", got, want)
	}
	if got := tcp.SchedulerMap; got != "edge-map" {
		t.Fatalf("tcp scheduler-map = %q, want edge-map", got)
	}

	iface := cfg.ClassOfService.Interfaces["ge-0/0/2"]
	if iface == nil {
		t.Fatal("expected ge-0/0/2 CoS interface (output-traffic-control-profile is a binding)")
	}
	unit := iface.Units[80]
	if unit == nil {
		t.Fatal("expected ge-0/0/2 unit 80 CoS binding")
	}
	// The make-or-break: the profile's shaping-rate materialized on the unit
	// shaper. RED on revert = 0 (silent zero-shaping).
	if got, want := unit.ShapingRateBytes, parseBandwidthLimit("9g"); got != want {
		t.Fatalf("unit shaping-rate after TCP resolution = %d, want %d (zero-shaping regression)", got, want)
	}
	if got := unit.SchedulerMap; got != "edge-map" {
		t.Fatalf("unit scheduler-map after TCP resolution = %q, want edge-map", got)
	}
	if got := unit.OutputTrafficControlProfile; got != "wan-tcp" {
		t.Fatalf("unit output-traffic-control-profile = %q, want wan-tcp", got)
	}
}

// TestCompileCoSTrafficControlProfileDirectUnitKnobWins pins the precedence: a
// direct unit-level shaping-rate / scheduler-map overrides the profile's
// (Junos gives an explicit unit binding precedence over the profile).
func TestCompileCoSTrafficControlProfileDirectUnitKnobWins(t *testing.T) {
	cfg := compileHB167(t, []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler be-sched",
		"set class-of-service scheduler-maps other-map forwarding-class best-effort scheduler be-sched",
		"set class-of-service schedulers be-sched transmit-rate 5g",
		"set class-of-service traffic-control-profiles wan-tcp shaping-rate 9g",
		"set class-of-service traffic-control-profiles wan-tcp scheduler-map edge-map",
		"set class-of-service interfaces ge-0/0/2 unit 80 output-traffic-control-profile wan-tcp",
		"set class-of-service interfaces ge-0/0/2 unit 80 shaping-rate 3g",
		"set class-of-service interfaces ge-0/0/2 unit 80 scheduler-map other-map",
		"set system dataplane-type userspace",
	})
	unit := cfg.ClassOfService.Interfaces["ge-0/0/2"].Units[80]
	if got, want := unit.ShapingRateBytes, parseBandwidthLimit("3g"); got != want {
		t.Fatalf("unit shaping-rate = %d, want %d (direct knob must win)", got, want)
	}
	if got := unit.SchedulerMap; got != "other-map" {
		t.Fatalf("unit scheduler-map = %q, want other-map (direct knob must win)", got)
	}
}

// TestCompileCoSTrafficControlProfileInterfaceLevel pins that an
// interface-level output-traffic-control-profile applies to every configured
// logical unit on the port (folded through applyCoSInterfaceLevelBindings then
// resolved).
func TestCompileCoSTrafficControlProfileInterfaceLevel(t *testing.T) {
	cfg := compileHB167(t, []string{
		"set interfaces ge-0/0/2 vlan-tagging",
		"set interfaces ge-0/0/2 unit 50 vlan-id 50",
		"set interfaces ge-0/0/2 unit 50 family inet address 172.16.50.8/24",
		"set interfaces ge-0/0/2 unit 80 vlan-id 80",
		"set interfaces ge-0/0/2 unit 80 family inet address 172.16.80.8/24",
		"set class-of-service traffic-control-profiles wan-tcp shaping-rate 9g",
		"set class-of-service interfaces ge-0/0/2 output-traffic-control-profile wan-tcp",
		"set system dataplane-type userspace",
	})
	iface := cfg.ClassOfService.Interfaces["ge-0/0/2"]
	if iface == nil {
		t.Fatal("expected ge-0/0/2 CoS interface")
	}
	for _, u := range []int{50, 80} {
		unit := iface.Units[u]
		if unit == nil {
			t.Fatalf("expected unit %d to inherit interface-level TCP binding", u)
		}
		if got, want := unit.ShapingRateBytes, parseBandwidthLimit("9g"); got != want {
			t.Fatalf("unit %d shaping-rate = %d, want %d", u, got, want)
		}
	}
}

// TestValidateCoSTrafficControlProfileAdvisories pins the two advisories:
// guaranteed-rate/delay-buffer-rate accepted-but-inert, and a dangling
// output-traffic-control-profile reference (inert / not shaped).
func TestValidateCoSTrafficControlProfileAdvisories(t *testing.T) {
	// guaranteed-rate / delay-buffer-rate inert advisory.
	cfg := compileHB167(t, []string{
		"set class-of-service traffic-control-profiles wan-tcp shaping-rate 9g",
		"set class-of-service traffic-control-profiles wan-tcp guaranteed-rate 2g",
		"set class-of-service interfaces ge-0/0/2 unit 80 output-traffic-control-profile wan-tcp",
		"set system dataplane-type userspace",
	})
	if !hasWarningContaining(ValidateConfig(cfg), "guaranteed-rate / delay-buffer-rate are accepted") {
		t.Fatalf("expected guaranteed-rate inert advisory, got %v", ValidateConfig(cfg))
	}

	// Dangling reference advisory.
	// #7337: dangling on purpose, so compile on the tolerant path where the
	// advisory under test is still what happens.
	cfg2 := compileHB167Lenient(t, []string{
		"set class-of-service interfaces ge-0/0/2 unit 80 output-traffic-control-profile missing-tcp",
		"set system dataplane-type userspace",
	})
	if !hasWarningContaining(ValidateConfig(cfg2), "undefined output-traffic-control-profile") {
		t.Fatalf("expected dangling TCP-reference advisory, got %v", ValidateConfig(cfg2))
	}
}
