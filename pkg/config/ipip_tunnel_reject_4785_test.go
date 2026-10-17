package config

import (
	"strings"
	"testing"
)

// #4785 half 1: `tunnel mode ipip` must be REJECTED at commit / commit-check.
//
// IPIP has no userspace dataplane primitive in either direction — an endpoint
// is entered into gre_decap_index only when tunnel_mode_kind() == TunnelKind::Gre,
// and TunnelKind::Unknown is the egress dispatcher's fail-closed drop arm — so
// the tunnel is created, comes UP, and passes no traffic at all. It previously
// committed green with only the #4788 advisory. This file replaces
// ipip_tunnel_dead_warn_4788_test.go: the advisory is now the gate's
// lenient-path warning, and the strict path errors.
//
// Both severities are pinned here, because a gate that rejects everywhere would
// brick the boot of a node whose ALREADY-COMMITTED config carries an IPIP
// stanza — the #1960 no-brick class covers a load that succeeds while revoking
// something, and it equally covers a load that refuses outright.

func ipipTree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestIpipTunnelRejectedAtCommit_4785 is the fail-on-revert guard for the strict
// path. It drives the REAL operator entry point (CompileConfig), not the gate
// function, so removing the wiring in compiler_tailgates.go fails it just as
// loudly as gutting the gate body.
func TestIpipTunnelRejectedAtCommit_4785(t *testing.T) {
	for _, tc := range []struct {
		name         string
		cmds         []string
		wantEndpoint string
	}{
		{
			// The inference case: the operator never types "ipip". An `ip-*`
			// interface defaults to mode ipip in compileInterfaces, so this is
			// the shape a real vSRX config arrives in.
			name: "interface-level, mode inferred from ip- prefix",
			cmds: []string{
				"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
			},
			wantEndpoint: "ip-0/0/0",
		},
		{
			// Explicit mode on a gr-* interface: the name says GRE, the mode
			// says ipip. The mode is what the dataplane classifies on.
			name: "explicit mode ipip on a gr- interface",
			cmds: []string{
				"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
				"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces gr-0/0/0 tunnel mode ipip",
			},
			wantEndpoint: "gr-0/0/0",
		},
		{
			name: "unit-level tunnel",
			cmds: []string{
				"set interfaces ip-0/0/1 unit 5 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/1 unit 5 tunnel destination 10.0.0.2",
			},
			wantEndpoint: "ip-0/0/1.5",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(ipipTree(t, tc.cmds...))
			if err == nil {
				t.Fatalf("CompileConfig ACCEPTED an ipip tunnel; the operator gets a "+
					"configured, UP interface that passes no traffic in either direction "+
					"and no error to act on (#4785). cmds: %v", tc.cmds)
			}
			// #4785 re-gate: assert the message CONTENT, not just that some
			// error occurred. A bare `err != nil` is one unrelated validator
			// away from passing for the wrong reason — which is exactly how the
			// WireGuard control in this file failed to fire.
			for _, want := range []string{
				"#4785",            // the tracking issue, so status is findable
				"mode gre",         // the working alternative
				"ipip",             // the cause
				"NOT implemented",  // that it is unimplemented, not misconfigured
				"either direction", // that it is dead both ways
				tc.wantEndpoint,    // WHICH emitted endpoint is dead
			} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("rejection message is missing %q — an operator needs the cause, "+
						"the affected endpoint and the alternative, not just a failure; "+
						"got: %v", want, err)
				}
			}
		})
	}
}

// TestIpipTunnelWarnsOnTolerantPath_4785 is the #1960 no-brick half. A config an
// older binary already committed (it was only an advisory then) must still LOAD
// — Store.Load and Store.SyncApply compile through CompileConfigLenient. A gate
// that rejected here would blackout-boot the node or alarm-loop HA config sync,
// which is a worse failure than the dead tunnel it is complaining about.
func TestIpipTunnelWarnsOnTolerantPath_4785(t *testing.T) {
	tree := ipipTree(t,
		"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
	)

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant load / peer-sync path must NOT reject an ipip tunnel — a "+
			"node whose already-committed config carries one would fail to boot (#1960): %v", err)
	}
	if cfg == nil {
		t.Fatal("lenient compile returned a nil config")
	}

	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4785") && strings.Contains(w, `"ip-0/0/0"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("the tolerant path must still WARN — a silently tolerated dead tunnel is "+
			"the pre-#4785 behaviour this change exists to end. warnings: %v", cfg.Warnings)
	}

	// The interface must still compile: the tolerant path tolerates, it does not
	// drop. A node that silently lost the stanza would diverge from its peer.
	if ifc := cfg.Interfaces.Interfaces["ip-0/0/0"]; ifc == nil || ifc.Tunnel == nil ||
		ifc.Tunnel.Mode != "ipip" {
		t.Errorf("lenient compile must preserve the tunnel config, got %+v",
			cfg.Interfaces.Interfaces["ip-0/0/0"])
	}
}

// TestIpipTunnelRejectionDoesNotOverreach_4785 is the over-rejection guard. The
// gate keys on the compiled MODE, so every other tunnel kind — and an `ip-*`
// interface with no tunnel stanza at all — must still commit. A gate that
// rejected these would take working GRE and WireGuard tunnels down.
func TestIpipTunnelRejectionDoesNotOverreach_4785(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{"gre by gr- prefix", []string{
			"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
			"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
		}},
		{"explicit mode gre on an ip- interface", []string{
			"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
			"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
			"set interfaces ip-0/0/0 tunnel mode gre",
		}},
		{"unit-level gre", []string{
			"set interfaces gr-0/0/1 unit 5 tunnel source 10.0.0.1",
			"set interfaces gr-0/0/1 unit 5 tunnel destination 10.0.0.2",
		}},
		{"ip- interface with no tunnel stanza", []string{
			"set interfaces ip-0/0/0 unit 0 family inet address 10.10.10.1/30",
		}},
		{"no interfaces at all", []string{
			"set system host-name fw1",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(ipipTree(t, tc.cmds...)); err != nil {
				t.Fatalf("the ipip gate must key on the compiled tunnel MODE and reject "+
					"nothing else; this commit failed: %v", err)
			}
		})
	}
}

// TestIpipTunnelGateReportsDeterministically_4785 pins the ordering contract the
// gate shares with its neighbours: names are walked sorted, so the FIRST
// reported error is stable across runs (Go map order is randomized) and both HA
// nodes report identically on the same config.
func TestIpipTunnelGateReportsDeterministically_4785(t *testing.T) {
	// Endpoints need source AND destination: the emitter screens a non-WireGuard
	// tunnel missing either, so a fixture without them emits nothing and the
	// test would assert on an empty set.
	tree := ipipTree(t,
		"set interfaces ip-0/0/9 tunnel source 10.0.9.1",
		"set interfaces ip-0/0/9 tunnel destination 10.0.9.2",
		"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces ip-0/0/5 tunnel source 10.0.5.1",
		"set interfaces ip-0/0/5 tunnel destination 10.0.5.2",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}

	for i := 0; i < 50; i++ {
		_, err := validateIpipTunnelUnimplementedStrict(cfg, false)
		if err == nil {
			t.Fatal("expected a rejection")
		}
		if !strings.Contains(err.Error(), `"ip-0/0/0"`) {
			t.Fatalf("first reported endpoint must be the lowest sorted name on every run "+
				"(Go map order is randomized, and both HA nodes must agree); iteration %d "+
				"got: %v", i, err)
		}
	}

	// The advisory reports every offender, in the same emitter order.
	warnings := validateIpipTunnelDeadWarning(cfg)
	if len(warnings) != 3 {
		t.Fatalf("advisory reported %d endpoints, want 3: %v", len(warnings), warnings)
	}
	for i, want := range []string{`"ip-0/0/0"`, `"ip-0/0/5"`, `"ip-0/0/9"`} {
		if !strings.Contains(warnings[i], want) {
			t.Errorf("advisory[%d] should name %s, got %q — ordered identities, not just a "+
				"count", i, want, warnings[i])
		}
	}
}

// TestIpipTunnelEffectiveGreStillCommits_4785 is the positive control the first
// round was missing, and the case that made the gate over-reject.
//
// An interface-level `tunnel` stanza on an `ip-*` interface compiles to mode
// ipip by default. A `unit 0 tunnel` stanza compiles to the SAME Linux device
// name (only unit N>0 gets a "uN" suffix), and the applier keys its desired set
// by that name with the unit record applied last — so when the unit resolves to
// gre, the realized device is a working GRE tunnel and the config must commit.
// Rejecting it is the same over-rejection keying on the interface NAME would
// have caused, reached one level in.
func TestIpipTunnelEffectiveGreStillCommits_4785(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{
			// Inherited parent: the interface names the mode, the unit inherits
			// it. Compiles to gre on both records.
			name: "unit inherits the parent's explicit gre",
			cmds: []string{
				"set interfaces ip-0/0/0 tunnel mode gre",
				"set interfaces ip-0/0/0 unit 0 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/0 unit 0 tunnel destination 10.0.0.2",
			},
		},
		{
			// Unit override: the interface record defaults to ipip, and unit 0
			// overrides to gre on the SAME device. The device is GRE.
			name: "unit 0 overrides an ip- interface to gre",
			cmds: []string{
				"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces ip-0/0/0 unit 0 tunnel mode gre",
			},
		},
		{
			name: "unit 0 overrides with a full gre tunnel stanza",
			cmds: []string{
				"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces ip-0/0/0 unit 0 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/0 unit 0 tunnel destination 10.0.0.2",
				"set interfaces ip-0/0/0 unit 0 tunnel mode gre",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(ipipTree(t, tc.cmds...)); err != nil {
				t.Fatalf("a config whose EFFECTIVE tunnel mode is gre was rejected — the "+
					"realized device is a working GRE tunnel and this is a new strict "+
					"failure on valid config (#4785): %v", err)
			}
		})
	}
}

// TestIpipTunnelInheritedByTunnellessUnitIsReported_4785 is the counter-case
// that keeps the shadowing fix honest, and it is the one the previous round got
// wrong in the OTHER direction.
//
// A unit with no `tunnel` stanza of its own still INHERITS the interface-level
// tunnel — EmitTunnelEndpointNames says so in a comment and emits it. The
// previous gate skipped exactly those units, so this config committed clean
// with the alarm surface silent, having been correctly rejected one commit
// earlier: unit 0's GRE record shadowed the interface record on the shared
// device key, and unit 2 — which emits ipip — was never visited.
//
// Measured at the pre-fix head e3754bc4c before this test was written:
// CompileConfig returned nil, ValidateConfig returned zero #4785 advisories,
// and the emitter published BOTH `ip-0/0/0.0` gre and `ip-0/0/0.2` ipip. A
// fixture that was green before and after would prove nothing.
func TestIpipTunnelInheritedByTunnellessUnitIsReported_4785(t *testing.T) {
	cmds := []string{
		"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces ip-0/0/0 unit 0 tunnel mode gre",
		"set interfaces ip-0/0/2 unit 2 family inet address 10.5.5.1/30",
	}
	// unit 2 lives on the SAME interface — it inherits the ipip parent.
	cmds[3] = "set interfaces ip-0/0/0 unit 2 family inet address 10.5.5.1/30"

	tree := ipipTree(t, cmds...)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a tunnel-less unit inherits the interface-level ipip tunnel and IS emitted " +
			"as an endpoint, so the config must be rejected. Accepting it commits a dead " +
			"tunnel silently — the under-rejection the emitter-based gate exists to close " +
			"(#4785)")
	}
	if !strings.Contains(err.Error(), "ip-0/0/0.2") {
		t.Errorf("the error must name the EMITTED endpoint that is dead, so an operator knows "+
			"which unit to fix; got: %v", err)
	}

	// The advisory path must report it too — that is the surface a box already
	// carrying this config sees.
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("tolerant compile: %v", lerr)
	}
	var found bool
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "ip-0/0/0.2") {
			found = true
		}
	}
	if !found {
		t.Errorf("ValidateConfig must report the inherited dead endpoint; warnings: %v",
			ValidateConfig(cfg))
	}
}

// TestIpipTunnelUnitOverrideCommitsButRaisesAnchorAlarm_4785 records the
// semantics the emitter-based gate corrects, AND the part the first version of
// this test got wrong.
//
// When an interface has units, emission publishes per-unit endpoints only — so
// `ip-0/0/0 tunnel src/dst` + `unit 1 tunnel mode gre` publishes exactly one
// endpoint, `ip-0/0/0.1` gre. No ipip endpoint reaches the dataplane, so the
// strict gate has nothing to reject and the config COMMITS.
//
// But "nothing dead reaches the dataplane" is a statement about the SNAPSHOT,
// not about the box. collectAppliedTunnels appends the interface-level record
// whenever Source != "" and the routing manager creates a mode-independent
// Tuntap anchor, so `ip-0-0-0` IS created with nothing routed through it. The
// acceptance was originally justified by a fact that did not cover that — the
// same incompleteness as the rejection it replaced, one round apart.
//
// Resolution: commit (the anchor breaks nothing and the unit tunnel is the
// likely intent) and raise a standing ADVISORY naming the orphan device.
func TestIpipTunnelUnitOverrideCommitsButRaisesAnchorAlarm_4785(t *testing.T) {
	tree := ipipTree(t,
		"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces ip-0/0/0 unit 1 tunnel mode gre",
	)

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	// The COUNT is asserted, not just the modes (#6861 F5): a loop over
	// "whatever exists" is satisfied by ZERO endpoints, so an emitter that
	// published nothing at all would score this premise green and the rest of
	// the test would then be measuring an empty config.
	eps := EmitTunnelEndpointNames(cfg)
	if len(eps) != 1 || eps[0].Name != "ip-0/0/0.1" || eps[0].Tunnel.Mode != "gre" {
		t.Fatalf("premise broken: this fixture must publish EXACTLY the one gre "+
			"endpoint ip-0/0/0.1 — an ipip endpoint would make it the strict gate's "+
			"subject, and zero endpoints would make the rest of this test vacuous. "+
			"got %d: %+v", len(eps), eps)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Errorf("no ipip endpoint is emitted, so the strict gate must not block the "+
			"commit: %v", err)
	}

	// ...but the orphan anchor must be named on the alarm surface.
	var anchorWarned bool
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "kernel anchor device") && strings.Contains(w, "ip-0-0-0") {
			anchorWarned = true
		}
	}
	if !anchorWarned {
		t.Errorf("the interface-level ipip stanza emits no endpoint but still creates the "+
			"anchor device ip-0-0-0 with nothing routed through it; `show system alarms` "+
			"must name it. warnings: %v", ValidateConfig(cfg))
	}
}

// TestIpipAnchorAlarmDoesNotOverreach_4785 is the advisory's negative control.
// The anchor warning must fire ONLY for an interface-level ipip record that
// emits nothing yet still creates a device — not for one that is already
// reported as a dead endpoint, not for GRE, and not for a record that creates
// no anchor at all because it has no source.
func TestIpipAnchorAlarmDoesNotOverreach_4785(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{"gre parent with a unit override", []string{
			"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
			"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
			"set interfaces gr-0/0/0 unit 1 tunnel mode gre",
		}},
		{"ipip parent that IS emitted (no units)", []string{
			"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
			"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
		}},
		{"ipip parent with no source creates no anchor", []string{
			"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
			"set interfaces ip-0/0/0 unit 1 tunnel mode gre",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(ipipTree(t, tc.cmds...))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			for _, w := range ValidateConfig(cfg) {
				if strings.Contains(w, "kernel anchor device") {
					t.Errorf("anchor advisory fired where no orphan anchor exists: %q", w)
				}
			}
		})
	}
}

// TestIpipTunnelWireguardStillCommits_4785 is the WireGuard positive control.
//
// The previous version could not fire. It used `tunnel listen-port`, which is
// not the syntax (`tunnel wireguard listen-port` is), so both fixtures were
// rejected EARLIER by the WireGuard validator and the ipip gate never ran on
// them — and the assertion was only "the error is not mine", which that earlier
// error satisfies. Mutating the gate to also flag `wireguard` left it PASSING.
//
// A positive control has to require the config to COMMIT. This asserts
// err == nil on a fixture that is complete enough to compile (private key and
// peer included, per tunnelid_test.go), so a gate that rejected WireGuard —
// the very mode the error message recommends — fails here.
func TestIpipTunnelWireguardStillCommits_4785(t *testing.T) {
	const (
		privKey = "985d0b677e48cc829d765cc606e0fa9a84ab3c8469f8bc04de7b52f096a731b6"
		peerKey = "6e2cc0919a4d6127938b531ab7cd6e69a908a780fd2b73083b31cba690abc177"
	)
	tree := ipipTree(t,
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key "+privKey,
		"set interfaces wg0 tunnel wireguard peer "+peerKey+" allowed-ips 10.0.0.0/24",
		"set interfaces wg0 unit 0 family inet address 10.70.0.1/30",
	)

	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a valid WireGuard tunnel must COMMIT — it is the mode the ipip error "+
			"message recommends, which would be a poor recommendation if the gate rejected "+
			"it: %v", err)
	}

	// And it must raise no standing alarm either.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "#4785") {
			t.Errorf("a WireGuard tunnel raised the ipip alarm: %q", w)
		}
	}
}

// TestIpipTunnelReportsEveryDeadEndpoint_4785 pins N5: the advisory lists ALL
// dead endpoints, not just the first. An operator with two dead tunnels who
// fixes one should not discover the second only on the next commit.
func TestIpipTunnelReportsEveryDeadEndpoint_4785(t *testing.T) {
	tree := ipipTree(t,
		"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces ip-0/0/1 tunnel source 10.0.1.1",
		"set interfaces ip-0/0/1 tunnel destination 10.0.1.2",
	)

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}

	seen := map[string]bool{}
	for _, w := range ValidateConfig(cfg) {
		if !strings.Contains(w, "#4785") {
			continue
		}
		for _, ep := range []string{"ip-0/0/0", "ip-0/0/1"} {
			if strings.Contains(w, ep) {
				seen[ep] = true
			}
		}
	}
	if len(seen) != 2 {
		t.Errorf("advisory reported %d of 2 dead endpoints (%v); truncating to the first "+
			"means an operator fixes one and finds the next only on the following commit",
			len(seen), seen)
	}

	// The tolerant path must not DOUBLE-report either (#4785 re-gate N1): the
	// lenient gate arm and the ValidateConfig registration both used to append.
	dupes := 0
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4785") {
			dupes++
		}
	}
	if dupes != 2 {
		t.Errorf("cfg.Warnings carries %d #4785 entries for 2 dead endpoints, want 2 — the "+
			"lenient gate arm and the ValidateConfig advisory must not both append", dupes)
	}
}

// TestIpipTunnelSurfacesOnAlarmPath_4785 is the alarm-surface registration pin.
//
// The strict gate covers the NEXT commit. It does not reach a box already
// carrying a dead tunnel: that generation was committed by an older build and
// loads leniently (#1960). The CLI and gRPC `show system alarms` views, and the
// two security-alarm views, all RECOMPUTE ValidateConfig from the ACTIVE config
// rather than reading cfg.Warnings — so an advisory that lives only in
// cfg.Warnings leaves those surfaces reporting "No alarms currently active"
// while the box forwards nothing. Removing the ValidateConfig registration is
// exactly that regression, and it is what this pins.
func TestIpipTunnelSurfacesOnAlarmPath_4785(t *testing.T) {
	cfg, err := CompileConfigLenient(ipipTree(t,
		"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
	))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}

	var found bool
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "#4785") && strings.Contains(w, `"ip-0/0/0"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("ValidateConfig does not surface the ipip advisory, so `show system alarms` "+
			"reports no alarms on a box whose tunnel passes no traffic. warnings: %v",
			ValidateConfig(cfg))
	}

	// Negative control: a working GRE tunnel must not raise a standing alarm.
	greCfg, err := CompileConfigLenient(ipipTree(t,
		"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
	))
	if err != nil {
		t.Fatalf("tolerant compile (gre): %v", err)
	}
	for _, w := range ValidateConfig(greCfg) {
		if strings.Contains(w, "#4785") {
			t.Errorf("a working GRE tunnel raised the ipip alarm: %q", w)
		}
	}
}
