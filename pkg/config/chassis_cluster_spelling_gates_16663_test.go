package config

import (
	"strings"
	"testing"
)

// #16663 (R3-A15-01): the four chassis-cluster raw-AST commit gates walked
// only the container spelling
//
//	chassis { cluster { ... } }
//
// via forEachChild(chassis.Children, "cluster", ...). The brace-top-level
// spelling #6672 made compile —
//
//	chassis cluster { ... }
//
// — puts the `cluster` keyword on the chassis node's own Keys, so
// FindChild("cluster") saw nothing and every gate stayed silent while the
// compiler (via normalizedClusterNode) compiled the body. A typo'd monitor
// weight committed as weight 0 (link-down deducts nothing, the RG never
// demotes), duplicate monitors, malformed RG / per-RG node ids and
// `preempt delay` all committed in that spelling while the container
// spelling rejected them.
//
// Fix: all four gates resolve the cluster body through
// normalizedClusterNode — the same view compileChassis reads — so every
// spelling in clusterSpellings (container, packed-in-chassis,
// packed-top-level, brace-top-level) is judged identically.
//
// FAIL-ON-REVERT (measured): restore any gate's
// `forEachChild(chassis.Children, "cluster", ...)` walk and the
// brace-top-level / packed rows below go RED. The container row uses the
// packed one-line body clusterSpellings renders, which even the OLD gates
// reached only via normalizedClusterNode's splitter — so on the pre-fix
// tree the helper reports the fixture bug ("container accepts ...") for
// the packed-body rows, and TestVA15Spellings_LenientWarns16663 fails
// naming the missing warning. The ValidBody control stays green either
// way, as a control must.

// spellingBody16663 renders one cluster body (packed one-line statement
// text, no trailing `;`) in every spelling clusterSpellings knows. The
// fixtures carry cluster-id + a >=16-char PSK + node 0 so the #6611
// auth-length gate cannot mask the gate under test.
func spellingBody16663(body string) map[string]string {
	full := "cluster-id 1 authentication-key test-cluster-psk-16663-long node 0 no-private-rg-election " + body
	return clusterSpellings(full)
}

// assertGateRejectsAllSpellings16663 requires the strict commit path to
// reject the fixture in EVERY spelling with the SAME message the
// container spelling produces. A nil container error fails the fixture
// itself (the test cannot show an escape if the oracle accepts).
func assertGateRejectsAllSpellings16663(t *testing.T, body, wantSubstr string) {
	t.Helper()
	spellings := spellingBody16663(body)

	containerErr := compileErr16663(t, spellings["container"])
	if containerErr == nil {
		t.Fatalf("fixture bug: the CONTAINER spelling accepts %q, so this "+
			"test cannot show another spelling escaping it", body)
	}
	if !strings.Contains(containerErr.Error(), wantSubstr) {
		t.Fatalf("container spelling rejected %q with %q, which does not "+
			"contain %q — wrong gate fired?", body, containerErr, wantSubstr)
	}
	for _, spelling := range []string{"packed-in-chassis", "packed-top-level", "brace-top-level"} {
		err := compileErr16663(t, spellings[spelling])
		if err == nil {
			t.Errorf("%s spelling of %q was ACCEPTED while the container "+
				"spelling was rejected with: %v", spelling, body, containerErr)
			continue
		}
		if err.Error() != containerErr.Error() {
			t.Errorf("%s spelling of %q was rejected by a DIFFERENT gate\n"+
				" container: %v\n %s: %v", spelling, body, containerErr, spelling, err)
		}
	}
}

// compileErr16663 parses src with the real hierarchical parser and returns
// the strict CompileConfig error (nil when the commit succeeds). It does
// NOT call SchemaValidate: these AST gates must fire on the compile path
// itself, exactly as runPreWalkGates invokes them.
func compileErr16663(t *testing.T, src string) error {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture parse errors: %v\n%s", errs, src)
	}
	_, err := CompileConfig(tree)
	return err
}

func compileOK16663(t *testing.T, src string) *Config {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture parse errors: %v\n%s", errs, src)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, src)
	}
	return cfg
}

// TestVA15Spellings_MonitorWeightGate16663 pins the #6588 monitor-weight
// gate (validateMonitorWeightTokensAST) across all spellings: a malformed
// weight and a duplicate weight with different values.
func TestVA15Spellings_MonitorWeightGate16663(t *testing.T) {
	t.Run("MalformedWeight", func(t *testing.T) {
		assertGateRejectsAllSpellings16663(t,
			"redundancy-group 1 node 0 priority 200 interface-monitor ge-0/0/1 weight 25O",
			`weight "25O" is not an integer`)
	})
	t.Run("DuplicateWeightDifferentValues", func(t *testing.T) {
		assertGateRejectsAllSpellings16663(t,
			"redundancy-group 1 node 0 priority 200 interface-monitor ge-0/0/1 weight 100 weight 200",
			"specified 2 times with different values")
	})
	t.Run("IPMonitoringGlobalWeight", func(t *testing.T) {
		assertGateRejectsAllSpellings16663(t,
			"redundancy-group 1 node 0 priority 200 ip-monitoring global-weight nope",
			`global-weight "nope" is not an integer`)
	})
}

// TestVA15Spellings_DuplicateMonitorGate16663 pins the #15036 duplicate
// interface-monitor rejection (same gate as the weight checks) across all
// spellings. Two separate `interface-monitor` statements for one interface
// are used so the packed splitter separates them into two statements.
func TestVA15Spellings_DuplicateMonitorGate16663(t *testing.T) {
	assertGateRejectsAllSpellings16663(t,
		"redundancy-group 1 node 0 priority 200 interface-monitor ge-0/0/1 weight 100 interface-monitor ge-0/0/1 weight 255",
		"duplicate interface-monitor ge-0/0/1")
}

// TestVA15Spellings_IdentityGate16663 pins the #5694 identity gate
// (validateChassisClusterIdentitiesAST) across all spellings: a malformed
// redundancy-group id and a malformed per-RG node id.
func TestVA15Spellings_IdentityGate16663(t *testing.T) {
	t.Run("MalformedRGID", func(t *testing.T) {
		assertGateRejectsAllSpellings16663(t,
			"redundancy-group reth0 node 0 priority 100",
			`"reth0" is not a valid non-negative integer id`)
	})
	t.Run("MalformedRGNodeID", func(t *testing.T) {
		assertGateRejectsAllSpellings16663(t,
			"redundancy-group 1 node one priority 100",
			`"one" is not a valid non-negative integer id`)
	})
}

// TestVA15Spellings_RGArityGate16663 pins the #6588 no-argument statement
// gate (validateRGNoArgStatementsAST) across all spellings: `preempt delay`
// is real Junos syntax xpf does not implement and must not be silently
// discarded in any spelling.
func TestVA15Spellings_RGArityGate16663(t *testing.T) {
	assertGateRejectsAllSpellings16663(t,
		"redundancy-group 1 node 0 priority 200 preempt delay 5",
		"preempt: takes no argument")
}

// TestVA15Spellings_GARPCountGate16663 pins the #5695 gratuitous-arp-count
// gate (validateGratuitousARPCountAST) across all spellings. This gate
// never rejects — it WARNS that an over-clamp count will be clamped — so
// every spelling must compile AND carry the same clamp warning.
func TestVA15Spellings_GARPCountGate16663(t *testing.T) {
	body := "redundancy-group 1 node 0 priority 200 gratuitous-arp-count 100000"

	container := compileOK16663(t, spellingBody16663(body)["container"])
	if !warningsContain(container.Warnings, "gratuitous-arp-count 100000 exceeds") {
		t.Fatalf("fixture bug: the CONTAINER spelling produced no clamp "+
			"warning, so this test cannot show another spelling escaping "+
			"it; warnings=%v", container.Warnings)
	}
	for _, spelling := range []string{"packed-in-chassis", "packed-top-level", "brace-top-level"} {
		cfg := compileOK16663(t, spellingBody16663(body)[spelling])
		if !warningsContain(cfg.Warnings, "gratuitous-arp-count 100000 exceeds") {
			t.Errorf("%s spelling of %q compiled WITHOUT the clamp warning "+
				"the container spelling emits; warnings=%v", spelling, body, cfg.Warnings)
		}
	}
}

// TestVA15Spellings_ValidBodyCommitsEverywhere16663 is the negative
// control: a well-formed cluster body — valid RG/node ids, a valid monitor
// weight, a bare `preempt` flag and an in-range gratuitous-arp-count —
// must still commit in every spelling, with no clamp warning. Green with
// and without the fix; it guards against the normalized walk inventing
// findings on valid packed input.
func TestVA15Spellings_ValidBodyCommitsEverywhere16663(t *testing.T) {
	body := "redundancy-group 1 node 0 priority 200 interface-monitor ge-0/0/1 weight 255 preempt gratuitous-arp-count 8"
	for spelling, src := range spellingBody16663(body) {
		cfg := compileOK16663(t, src)
		if cfg.Chassis.Cluster == nil {
			t.Errorf("%s spelling compiled no cluster config", spelling)
			continue
		}
		if warningsContain(cfg.Warnings, "gratuitous-arp-count") {
			t.Errorf("%s spelling warned on an in-range count; warnings=%v",
				spelling, cfg.Warnings)
		}
	}
}

// TestVA15Spellings_LenientWarns16663 pins the #1960 no-brick posture in
// the previously-escaping spelling: on the tolerant load / peer-sync path
// the same malformed weight WARNS (does not error) and still compiles.
func TestVA15Spellings_LenientWarns16663(t *testing.T) {
	body := "redundancy-group 1 node 0 priority 200 interface-monitor ge-0/0/1 weight 25O"
	for _, spelling := range []string{"brace-top-level", "packed-top-level"} {
		tree, errs := NewParser(spellingBody16663(body)[spelling]).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("%s: lenient compile must not reject (no-brick), got %v", spelling, err)
		}
		if !warningsContain(cfg.Warnings, `weight "25O" is not an integer`) {
			t.Errorf("%s: lenient compile should have warned about the "+
				"malformed weight; warnings=%v", spelling, cfg.Warnings)
		}
	}
}
