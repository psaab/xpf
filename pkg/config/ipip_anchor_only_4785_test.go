package config

import (
	"strings"
	"testing"
)

// #4785 fold F2 + F3: the anchor-only advisory.
//
// F2 (a REGRESSION this PR introduced). The #4788 advisory it replaced walked
// UNITS as well as interfaces. The replacement examined only `iface.Tunnel`,
// while daemon collection (collectAppliedTunnels, pkg/daemon/daemon_run_routehelpers.go)
// applies EVERY non-nil `unit.Tunnel` with no completeness screen at all and
// routing then creates a mode-independent Tuntap anchor. So
//
//	set interfaces ip-0/0/0 unit 5 tunnel destination 10.0.0.2
//
// emitted nothing (the emitter suppresses a non-WireGuard endpoint missing
// either half), which is exactly why the strict gate is silent for it by
// design — and it also produced NO advisory, while still creating a visible
// `ip-0-0-0u5` device carrying nothing. Neither rejection nor alarm, which
// contradicts the reason the advisory is registered at all.
//
// F3 (wrong cause in a diagnostic). The advisory always said "no tunnel endpoint
// is emitted for the interface-level stanza (every unit overrides it)". For a
// source-only interface stanza with NO units that diagnosis is false and its
// per-unit remediation is the wrong advice.

// ipipWarningsFor compiles and returns the ValidateConfig warnings mentioning
// ipip — the REAL alarm entry point, not ipipAnchorOnlyWarnings directly. The
// alarm surfaces (`show system alarms`, gRPC, the two security-alarm views)
// recompute ValidateConfig from the ACTIVE config, so that is the path that has
// to carry the advisory.
func ipipWarningsFor(t *testing.T, cmds ...string) []string {
	t.Helper()
	cfg, err := CompileConfig(ipipTree(t, cmds...))
	if err != nil {
		t.Fatalf("compile must SUCCEED for these fixtures (nothing is emitted, so the "+
			"strict gate is silent by design): %v", err)
	}
	if got := len(EmitTunnelEndpointNames(cfg)); got != 0 {
		t.Fatalf("fixture emits %d endpoint(s); it must emit NONE, otherwise the strict "+
			"gate covers it and the advisory is not what is under test", got)
	}
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "ipip") {
			out = append(out, w)
		}
	}
	return out
}

// ipipWgIfaceStanza is the interface-level WireGuard stanza the slot-cause
// fixtures share. WireGuard only compiles with a listen-port, a decodable
// private key, and at least one peer; `tunnel wireguard listen-port` is the real
// syntax (a bare `tunnel listen-port` parses into a leaf nothing reads and would
// leave the fixture unable to compile).
func ipipWgIfaceStanza() []string {
	return []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " +
			"a39d0711b6f83a027999f8284a0da677bb2c08c898dca1ef15d12428f7e242bf",
		"set interfaces wg0 tunnel wireguard peer " +
			"2d1c7eeb0cc094f26b60bb510fcbd08640d469f55684271991b4d6d349b8cdf3 " +
			"allowed-ips 10.0.0.0/24",
	}
}

// TestIpipUnitAnchorStillAlarms_4785 is the F2 fail-on-revert guard: a unit-level
// ipip record that emits nothing must still raise the standing alarm, because
// the daemon still builds it an anchor.
//
// RED-on-revert: drop the unit walk from ipipAnchorOnlyWarnings and this fails
// at "creates a kernel anchor ... but raised NO alarm".
//
// The unit number is asserted EXACTLY, not via the bare word "unit" (#6861 F2b).
// Production formats it (ipipAnchorOnlyWarnings: `interfaces %q unit %d`), and
// the bare-word form passed for any unit number at all — so a walk that reported
// the wrong unit, which is precisely the kind of off-by-one an operator cannot
// recover from because they would go edit a stanza that is not the dead one,
// scored green. The merge-base assertion this file's F2 work replaced did check
// the number; that strength is restored here.
func TestIpipUnitAnchorStillAlarms_4785(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cmds     []string
		wantUnit string
		want     string
	}{
		{
			// The F2 shape verbatim: destination only, no source.
			name:     "destination_only",
			cmds:     []string{"set interfaces ip-0/0/0 unit 5 tunnel destination 10.0.0.2"},
			wantUnit: `interfaces "ip-0/0/0" unit 5 tunnel mode ipip`,
			want:     "no `tunnel source` is configured",
		},
		{
			// #6861 F4: NEITHER half. This was covered by the deleted
			// TestIpipTunnelDeadWarning and was lost in the relocation — the
			// two cases above are source-only and destination-only, so a unit
			// loop that skipped records with both halves empty stayed green
			// across the whole suite. Production warns correctly; only the
			// guard was missing.
			name:     "neither_source_nor_destination",
			cmds:     []string{"set interfaces ip-0/0/2 unit 7 tunnel mode ipip"},
			wantUnit: `interfaces "ip-0/0/2" unit 7 tunnel mode ipip`,
			want:     "neither `tunnel source` nor `tunnel destination` is configured",
		},
		{
			// The mirror: source only. collectAppliedTunnels screens the
			// INTERFACE level on Source != "" but screens units on nothing, so
			// this is an anchor too.
			name:     "source_only",
			cmds:     []string{"set interfaces ip-0/0/1 unit 3 tunnel source 10.0.0.1"},
			wantUnit: `interfaces "ip-0/0/1" unit 3 tunnel mode ipip`,
			want:     "no `tunnel destination` is configured",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warns := ipipWarningsFor(t, tc.cmds...)
			if len(warns) == 0 {
				t.Fatalf("a unit-level ipip stanza creates a kernel anchor device the "+
					"operator can see, but raised NO alarm: it gets neither the strict "+
					"rejection (nothing is emitted) nor the standing advisory, so a dead "+
					"tunnel is invisible on a box already carrying it (#4785 F2). cmds=%v",
					tc.cmds)
			}
			joined := strings.Join(warns, "\n")
			// The trailing " tunnel mode ipip" is part of the wanted string on
			// purpose (#6861 F5): production formats `interfaces %q unit %d`, so
			// a bare `unit 5` is a strict PREFIX of `unit 50` and a Contains
			// check on it stays GREEN when the formatter reports the wrong unit
			// as long as the right one is a prefix. Anchoring on the next token
			// closes that.
			if !strings.Contains(joined, tc.wantUnit) {
				t.Errorf("the advisory must name the EXACT interface and unit the dead "+
					"anchor belongs to, want %q; an advisory naming some other unit sends "+
					"the operator to edit a stanza that is not the dead one. got %q",
					tc.wantUnit, joined)
			}
			if !strings.Contains(joined, tc.want) {
				t.Errorf("advisory must give the real cause %q; got %q", tc.want, joined)
			}
		})
	}
}

// TestIpipSharedDeviceWithEmittedEndpointIsNotAnchorOnly_6861 is the fail-on-revert
// guard for the F1b fix: the anchor determination keys on the RUNTIME DEVICE
// NAME, not on *TunnelConfig pointer identity.
//
// Pointer identity answers "is this record the object the emitter published".
// The advisory's claim is about a Linux device — "an interface an operator can
// see that carries no traffic" — and in both shapes below an UNEMITTED record
// names the SAME device an emitted endpoint binds to. Reported as dead, each is
// a false alarm against live, traffic-carrying infrastructure, and each carries
// a remediation telling the operator to delete it.
//
// RED-on-revert: restore the `emitted map[*TunnelConfig]bool` test and both
// sub-cases fail at "declared DEAD ... but that device carries the emitted".
func TestIpipSharedDeviceWithEmittedEndpointIsNotAnchorOnly_6861(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cmds       []string
		wantRef    string // the emitted endpoint ref
		wantDevice string // the device that ref resolves to
		// candidate is the UNEMITTED ipip record whose suppression is under
		// test. Asserting it is really ipip is not redundant (#6861 F5):
		// without it, flipping this record to gre leaves the subtest GREEN —
		// silent for the MODE reason instead of the shared-device reason, so
		// the assertion below would no longer be measuring anything.
		candidate func(*Config) *TunnelConfig
		why       string
	}{
		{
			// compiler_interfaces.go gives unit 0's per-unit tunnel the BASE
			// Linux name — identical to the interface-level record's — and
			// pkg/routing/tunnel.go keys its desired set by that name, so the
			// two records are ONE device. The emitter publishes the unit's GRE
			// pointer (#5635), leaving the interface pointer unemitted.
			name: "gre_unit0_shares_the_base_device",
			cmds: []string{
				"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces ip-0/0/0 unit 0 tunnel mode gre",
			},
			wantRef:    "ip-0/0/0.0",
			wantDevice: "ip-0-0-0",
			candidate: func(c *Config) *TunnelConfig {
				return c.Interfaces.Interfaces["ip-0/0/0"].Tunnel
			},
			why: "the interface-level ipip record and unit 0's GRE record carry the " +
				"SAME Linux device name, and that device is the one the working GRE " +
				"tunnel runs on",
		},
		{
			// Interface-level WireGuard short-circuits the emitter to ONE
			// endpoint keyed by the lowest unit, carrying the INTERFACE-level
			// pointer (#1910) — but TunnelNameMap resolves that ref to the
			// UNIT's device, which is what snapshotLinuxName writes into
			// InterfaceSnapshot.LinuxName and therefore what the tunnel
			// endpoint (and the Rust WireGuard TUN behind it) binds to.
			name: "wireguard_endpoint_binds_the_units_device",
			cmds: append(ipipWgIfaceStanza(),
				"set interfaces wg0 unit 3 tunnel mode ipip",
				"set interfaces wg0 unit 3 tunnel source 10.0.0.1",
				"set interfaces wg0 unit 3 tunnel destination 10.0.0.2",
			),
			wantRef:    "wg0.3",
			wantDevice: "wg0u3",
			candidate: func(c *Config) *TunnelConfig {
				return c.Interfaces.Interfaces["wg0"].Units[3].Tunnel
			},
			why: "the sole unit is the lowest, so the emitted WireGuard endpoint is " +
				"keyed to it and resolves to the unit's own device — live WireGuard " +
				"infrastructure, not a dead IPIP anchor",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(ipipTree(t, tc.cmds...))
			if err != nil {
				t.Fatalf("compile must SUCCEED — the emitted endpoint is not ipip: %v", err)
			}

			// PRECONDITIONS. Without these a fixture that drifted into some
			// other shape would pass for the wrong reason: it must really emit
			// the endpoint, and that endpoint must really resolve to the device
			// the unemitted ipip record names.
			eps := EmitTunnelEndpointNames(cfg)
			if len(eps) != 1 || eps[0].Name != tc.wantRef {
				t.Fatalf("fixture must emit exactly one endpoint %q, got %d: %+v",
					tc.wantRef, len(eps), eps)
			}
			if eps[0].Tunnel.Mode == "ipip" {
				t.Fatalf("fixture's EMITTED endpoint is itself ipip; that makes this the "+
					"strict gate's subject, not the anchor advisory's: %+v", eps[0])
			}
			cand := tc.candidate(cfg)
			if cand == nil || cand.Mode != "ipip" {
				t.Fatalf("fixture precondition: the UNEMITTED record under test must "+
					"carry mode ipip, else this subtest passes because the advisory "+
					"skips it on MODE and proves nothing about the shared device: %+v",
					cand)
			}
			if cand.Name != tc.wantDevice {
				t.Fatalf("fixture precondition: the unemitted record's anchor device "+
					"must be %q — the same device the emitted endpoint binds to — or "+
					"there is no collision to suppress; got %q", tc.wantDevice, cand.Name)
			}
			if got := cfg.TunnelNameMap()[tc.wantRef]; got != tc.wantDevice {
				t.Fatalf("fixture precondition: the emitted ref %q must resolve to device "+
					"%q (the same name the unemitted ipip record carries) or this test is "+
					"not exercising the shared-device collision at all; got %q",
					tc.wantRef, tc.wantDevice, got)
			}

			// Drive the REAL alarm entry point: `show system alarms` and the two
			// security-alarm views recompute ValidateConfig from the active config.
			var warns []string
			for _, w := range ValidateConfig(cfg) {
				if strings.Contains(w, "ipip") {
					warns = append(warns, w)
				}
			}
			if len(warns) != 0 {
				t.Errorf("device %q was declared DEAD (\"carries no traffic\") but that "+
					"device carries the emitted endpoint %q — %s. The advisory reaches the "+
					"boot/apply log and `show system alarms`, and its remediation tells the "+
					"operator to delete the stanza, so this is a false alarm aimed at live "+
					"config (#6861 F1b). advisories: %v",
					tc.wantDevice, tc.wantRef, tc.why, warns)
			}
		})
	}
}

// TestIpipIncompleteAnchorNamesTheRealCause_4785 is the F3 guard. A source-only
// interface stanza with NO units at all must not be diagnosed as "every unit
// overrides it" — there are no units.
//
// RED-on-revert: restore the single hard-coded cause string and this fails at
// "diagnosed as overridden-by-units".
func TestIpipIncompleteAnchorNamesTheRealCause_4785(t *testing.T) {
	warns := ipipWarningsFor(t, "set interfaces ip-0/0/2 tunnel source 10.0.0.1")
	if len(warns) != 1 {
		t.Fatalf("expected exactly 1 anchor advisory, got %d: %v", len(warns), warns)
	}
	w := warns[0]
	if strings.Contains(w, "every unit overrides it") {
		t.Errorf("a stanza with NO units was diagnosed as overridden-by-units, and the "+
			"remediation it gives (remove the interface-level stanza so the per-unit "+
			"tunnels win) is the wrong advice for a config that has none: %q", w)
	}
	if !strings.Contains(w, "no `tunnel destination` is configured") {
		t.Errorf("the advisory must name the real cause — the endpoint is incomplete, so "+
			"the emitter suppressed it: %q", w)
	}
}

// TestIpipOverriddenAnchorKeepsTheOverrideCause_4785 is the over-reach guard for
// F3: the genuine every-unit-overrides shape must KEEP its original diagnosis
// and its original remediation. Splitting the cause must not collapse both arms
// onto the new wording.
//
// Stays GREEN under the F3 revert (both arms said this before), and is what
// stops the F3 fix from being a blanket rewording.
func TestIpipOverriddenAnchorKeepsTheOverrideCause_4785(t *testing.T) {
	// The interface record is COMPLETE, so nothing about it is incomplete; it is
	// unemitted purely because the single unit carries its own tunnel.
	cfg, err := CompileConfig(ipipTree(t,
		"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces ip-0/0/0 unit 1 tunnel mode gre",
		"set interfaces ip-0/0/0 unit 1 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 unit 1 tunnel destination 10.0.0.3",
	))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	warns := ipipAnchorOnlyWarnings(cfg)
	if len(warns) != 1 {
		t.Fatalf("expected exactly 1 anchor advisory for the overridden interface "+
			"stanza, got %d: %v", len(warns), warns)
	}
	if !strings.Contains(warns[0], "every unit overrides it") {
		t.Errorf("the genuine override shape lost its diagnosis: %q", warns[0])
	}
	if !strings.Contains(warns[0], "Removing the interface-level `tunnel` stanza") {
		t.Errorf("the genuine override shape lost its remediation: %q", warns[0])
	}
}

// TestIpipRemediationsNeverInstructTrafficLoss_6861 binds the #6861 F1b
// remediation rule: an advisory that reaches the boot/apply log and
// `show system alarms` must never tell an operator to delete config that is
// carrying traffic.
//
// Each arm asserts the corrected text AND separately PROVES the hazard by
// compiling the config the old remediation described — so the assertions are
// anchored to a demonstrated consequence rather than to a wording preference.
// Without the proofs an assertion on advisory text is only a restatement of
// whatever string production happens to hold.
//
// RED-on-revert: restore either old remediation and the matching arm fails at
// "still offers the deletion".
func TestIpipRemediationsNeverInstructTrafficLoss_6861(t *testing.T) {
	// ARM 1 — the INTERFACE-level branch. The old text was an unconditional
	// "Remove the interface-level `tunnel` stanza if the per-unit tunnels are
	// the intent." A unit tunnel is built by cloneForUnit FROM the interface
	// record and only then takes its own overrides, so a unit carrying just
	// `tunnel mode gre` holds INHERITED endpoints.
	t.Run("interface_branch_warns_about_inheritance", func(t *testing.T) {
		inheriting := []string{
			"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
			"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
			"set interfaces ip-0/0/0 unit 1 tunnel mode gre",
		}
		cfg, err := CompileConfig(ipipTree(t, inheriting...))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if got := len(EmitTunnelEndpointNames(cfg)); got != 1 {
			t.Fatalf("precondition: the inheriting unit must emit a working GRE "+
				"endpoint, got %d", got)
		}
		warns := ipipAnchorOnlyWarnings(cfg)
		if len(warns) != 1 {
			t.Fatalf("expected exactly 1 anchor advisory, got %d: %v", len(warns), warns)
		}
		if !strings.Contains(warns[0], "INHERITS them from this stanza") {
			t.Errorf("the remediation does not warn that removing the interface-level "+
				"stanza strips the endpoints inheriting units are built from, so an "+
				"operator who complies silently kills a working tunnel (#6861 F1b): %q",
				warns[0])
		}

		// THE PROOF. Compile exactly what the old remediation instructed —
		// the same config with the interface-level `tunnel` stanza removed.
		stripped, err := CompileConfig(ipipTree(t, inheriting[2]))
		if err != nil {
			t.Fatalf("compile without the interface-level stanza: %v", err)
		}
		if got := len(EmitTunnelEndpointNames(stripped)); got != 0 {
			t.Fatalf("this arm's premise is stale: removing the interface-level stanza "+
				"was expected to leave the unit with no endpoints and emit NOTHING, but "+
				"it emitted %d. Re-derive the hazard before trusting the assertion "+
				"above", got)
		}
	})

	// ARM 2 — the UNIT branch under interface-level WireGuard. The old text
	// offered "or remove the interface-level `tunnel` stanza if the per-unit
	// tunnels are the intent" as an alternative, and NOTHING tested that
	// branch. It is doubly unsafe: it deletes the working WireGuard tunnel and
	// it exposes the complete ipip unit underneath.
	t.Run("wireguard_unit_branch_refuses_the_parent_removal", func(t *testing.T) {
		unitStanza := []string{
			"set interfaces wg0 vlan-tagging",
			"set interfaces wg0 unit 1 vlan-id 1",
			"set interfaces wg0 unit 1 family inet address 10.1.1.1/30",
			"set interfaces wg0 unit 3 tunnel mode ipip",
			"set interfaces wg0 unit 3 tunnel source 10.0.0.1",
			"set interfaces wg0 unit 3 tunnel destination 10.0.0.2",
		}
		cfg, err := CompileConfig(ipipTree(t, append(ipipWgIfaceStanza(), unitStanza...)...))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		warns := ipipAnchorOnlyWarnings(cfg)
		if len(warns) != 1 {
			t.Fatalf("expected exactly 1 anchor advisory, got %d: %v", len(warns), warns)
		}
		if strings.Contains(warns[0], "remove the interface-level `tunnel` stanza if the") {
			t.Errorf("the advisory still offers the deletion of the interface-level "+
				"WireGuard stanza as an alternative remediation (#6861 F1b): %q", warns[0])
		}
		if !strings.Contains(warns[0], "do NOT remove that interface-level stanza") {
			t.Errorf("the advisory does not warn the operator off the parent removal, "+
				"leaving the more destructive of the two obvious moves unmarked: %q",
				warns[0])
		}

		// THE PROOF. Compile exactly what the old alternative instructed —
		// the same config with the interface-level WireGuard stanza removed.
		// The ipip unit is now the emitted endpoint, and the strict gate that
		// is the whole point of #4785 half 1 rejects it.
		_, err = CompileConfig(ipipTree(t, unitStanza...))
		if err == nil {
			t.Fatal("this arm's premise is stale: removing the interface-level " +
				"WireGuard stanza was expected to expose the complete ipip unit to the " +
				"strict gate, but the config compiled clean. Re-derive the hazard " +
				"before trusting the assertion above")
		}
		if !strings.Contains(err.Error(), `tunnel endpoint "wg0.3" has mode ipip`) {
			t.Errorf("the exposed endpoint must be the ipip unit the advisory is "+
				"about; a different rejection means the proof is not measuring the "+
				"hazard: %v", err)
		}
	})

	// ARM 3 — the incomplete-endpoint branch is SHARED by interface and unit
	// records, so its "or remove the `tunnel` stanza" was ambiguous at the
	// interface site in exactly the same way. The unit site scopes the
	// deletion to the unit; the interface site carries the inheritance caveat.
	t.Run("incomplete_branch_scopes_the_deletion", func(t *testing.T) {
		// Interface record, incomplete, with a unit that COMPLETES it by
		// inheriting the source — so the deletion really would cost traffic.
		completing := []string{
			"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
			"set interfaces ip-0/0/0 unit 1 tunnel destination 10.0.0.2",
		}
		if _, err := CompileConfig(ipipTree(t, completing...)); err == nil {
			t.Fatal("precondition: the inheriting unit resolves to a complete IPIP " +
				"endpoint, so the strict gate must reject this config")
		}
		lenientCfg, err := CompileConfigLenient(ipipTree(t, completing...))
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		if got := len(EmitTunnelEndpointNames(lenientCfg)); got != 1 {
			t.Fatalf("precondition: the unit must emit by inheriting the "+
				"interface-level source, got %d", got)
		}
		ifaceWarn := ipipAnchorOnlyWarnings(lenientCfg)
		if len(ifaceWarn) != 1 {
			t.Fatalf("expected exactly 1 anchor advisory, got %d: %v",
				len(ifaceWarn), ifaceWarn)
		}
		if !strings.Contains(ifaceWarn[0], "no `tunnel destination` is configured") {
			t.Fatalf("precondition: this must be the incomplete branch: %q", ifaceWarn[0])
		}
		if !strings.Contains(ifaceWarn[0], "INHERITS them from this stanza") {
			t.Errorf("the incomplete branch's interface-site remediation drops the "+
				"inheritance caveat, so it repeats the unsafe instruction the complete "+
				"branch was fixed for (#6861 F1b): %q", ifaceWarn[0])
		}

		// Unit record, incomplete: the deletion must be scoped to the unit.
		unitCfg, err := CompileConfig(ipipTree(t,
			"set interfaces ip-0/0/1 unit 3 tunnel source 10.0.0.1"))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		unitWarn := ipipAnchorOnlyWarnings(unitCfg)
		if len(unitWarn) != 1 {
			t.Fatalf("expected exactly 1 anchor advisory, got %d: %v",
				len(unitWarn), unitWarn)
		}
		if !strings.Contains(unitWarn[0], "remove THIS UNIT's `tunnel` stanza") {
			t.Errorf("a unit-site remediation must scope the deletion to the unit; the "+
				"bare \"remove the `tunnel` stanza\" reads as the interface-level one: %q",
				unitWarn[0])
		}
	})
}

// TestIpipAnchorAdvisoryIgnoresGre_4785 is the over-reach guard for the MODE.
// The unit walk added for F2 must not start alarming on working tunnels: a
// GRE unit record that emits nothing is not a #4785 dead tunnel.
//
// Stays GREEN under the revert.
func TestIpipAnchorAdvisoryIgnoresGre_4785(t *testing.T) {
	cfg, err := CompileConfig(ipipTree(t,
		"set interfaces gr-0/0/0 unit 5 tunnel destination 10.0.0.2",
	))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got := len(EmitTunnelEndpointNames(cfg)); got != 0 {
		t.Fatalf("fixture must emit nothing, got %d", got)
	}
	if warns := ipipAnchorOnlyWarnings(cfg); len(warns) != 0 {
		t.Errorf("a GRE unit record raised an IPIP dead-tunnel advisory — the unit walk "+
			"must key on mode, not on being unemitted: %v", warns)
	}
}

// TestIpipEmittedUnitIsNotDoubleReported_4785 is the over-reach guard for the
// EMISSION screen. A unit whose endpoint IS emitted belongs to the strict gate;
// the anchor advisory must not also claim it, or every rejected config would
// carry a duplicate paragraph about the same tunnel.
//
// Stays GREEN under the revert.
func TestIpipEmittedUnitIsNotDoubleReported_4785(t *testing.T) {
	cfg, err := CompileConfigLenient(ipipTree(t,
		"set interfaces ip-0/0/0 unit 5 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 unit 5 tunnel destination 10.0.0.2",
	))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if got := len(EmitTunnelEndpointNames(cfg)); got != 1 {
		t.Fatalf("fixture must emit exactly 1 endpoint, got %d", got)
	}
	if warns := ipipAnchorOnlyWarnings(cfg); len(warns) != 0 {
		t.Errorf("an EMITTED unit endpoint was also reported as anchor-only; it is the "+
			"strict gate's (and the dead-endpoint advisory's) subject, not this one's: %v",
			warns)
	}
}

// #6861 F1: the COMPLETE-but-unemitted fallback was shared between the
// interface and unit call sites, so a unit record was reported with the
// interface record's cause and remediation.
//
// The interface-level `tunnel mode wireguard` stanza short-circuits the
// emitter to ONE endpoint keyed by the lowest unit (#1910) and never visits
// the per-unit records, while collectAppliedTunnels applies EVERY non-nil
// unit.Tunnel with no screen at all — so a unit overriding to `mode ipip`
// with both endpoints set is complete, unemitted, and still gets a kernel
// anchor. It used to be told "no tunnel endpoint is emitted for the
// interface-level stanza (every unit overrides it)", which named a unit and
// then explained the interface, inverted the direction of the suppression, and
// pointed remediation at a stanza that is not the one to touch first.
//
// TestIpipOverriddenAnchorKeepsTheOverrideCause_4785 above is the reason this
// went unnoticed: it drives the INTERFACE branch, where that same default text
// is CORRECT. It stays green under the revert; this one does not.
func TestIpipUnitUnderWireguardNamesTheSlotCause_6861(t *testing.T) {
	// Fixture: unit 1 carries no `tunnel` stanza of its own, so it is the LOWEST
	// unit AND resolves to the shared `wg0` device — which is what makes unit 3's
	// `wg0u3` a genuinely dead anchor rather than the device the WireGuard
	// endpoint binds to. The original single-unit-3 fixture is the shape #6861
	// F1b proved is NOT dead (the WG endpoint keys to the sole unit and resolves
	// to `wg0u3`); it now lives in
	// TestIpipSharedDeviceWithEmittedEndpointIsNotAnchorOnly_6861 as a must-be-
	// silent case. The endpoint-bearing unit here is a genuine override — both
	// halves set — so ipipMissingEndpointHalves returns "" and the COMPLETE
	// fallback is what renders.
	cfg, err := CompileConfig(ipipTree(t, append(ipipWgIfaceStanza(),
		"set interfaces wg0 unit 1 family inet address 10.1.1.1/30",
		"set interfaces wg0 unit 3 tunnel mode ipip",
		"set interfaces wg0 unit 3 tunnel source 10.0.0.1",
		"set interfaces wg0 unit 3 tunnel destination 10.0.0.2",
	)...))
	if err != nil {
		t.Fatalf("compile must SUCCEED — the ipip unit emits nothing, so the strict "+
			"gate is silent for it by design: %v", err)
	}

	// PRECONDITION, so a fixture that drifts into some other shape fails loudly
	// instead of passing for the wrong reason. Exactly one endpoint is emitted,
	// it is the interface-level WireGuard object keyed by the lowest unit, and
	// the unit's own ipip endpoint is NOT among them.
	eps := EmitTunnelEndpointNames(cfg)
	if len(eps) != 1 || eps[0].Name != "wg0.1" || eps[0].Tunnel.Mode != "wireguard" {
		t.Fatalf("fixture must emit exactly the interface-level WireGuard endpoint "+
			"keyed by the lowest unit; the unit's ipip endpoint being emitted would "+
			"make this the strict gate's subject, not the advisory's. got %d: %+v",
			len(eps), eps)
	}
	// The dead anchor must be a DIFFERENT device from the one the emitted
	// WireGuard endpoint binds to; if they coincide, unit 3 is live and this
	// test is asserting an advisory that should not exist at all (#6861 F1b).
	names := cfg.TunnelNameMap()
	if names["wg0.1"] != "wg0" || names["wg0u3"] == "wg0" || names["wg0.3"] != "wg0u3" {
		t.Fatalf("fixture precondition: the emitted endpoint must resolve to `wg0` and "+
			"unit 3 to a SEPARATE `wg0u3` device, else the anchor is not dead: %v", names)
	}
	unit := cfg.Interfaces.Interfaces["wg0"].Units[3]
	if unit == nil || unit.Tunnel == nil || unit.Tunnel.Mode != "ipip" ||
		unit.Tunnel.Source == "" || unit.Tunnel.Destination == "" {
		t.Fatalf("fixture must leave unit 3 carrying a COMPLETE ipip override — an "+
			"incomplete one takes the missing-halves branch and this test would be "+
			"measuring the wrong arm: %+v", unit)
	}

	// Drive the REAL alarm entry point, not ipipAnchorOnlyWarnings, so the
	// ValidateConfig wiring is bound too.
	var warns []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "ipip") {
			warns = append(warns, w)
		}
	}
	if len(warns) != 1 {
		t.Fatalf("expected exactly 1 ipip advisory for the anchor-only unit, got %d: %v",
			len(warns), warns)
	}
	got := warns[0]

	// Anchored past the number for the same reason as F5 above: bare `unit 3`
	// is a prefix of `unit 30`.
	if !strings.Contains(got, `interfaces "wg0" unit 3 tunnel mode ipip`) {
		t.Errorf("the advisory does not name the unit it is about: %q", got)
	}
	// The three ways the shared interface text was wrong here.
	if strings.Contains(got, "every unit overrides it") {
		t.Errorf("a UNIT record was given the INTERFACE record's cause: the "+
			"interface-level stanza suppressed this unit, not the units overriding "+
			"the interface — the direction is inverted (#6861 F1): %q", got)
	}
	if !strings.Contains(got, "interface-level `tunnel mode wireguard` stanza takes the") {
		t.Errorf("the advisory does not name the interface-level WireGuard stanza "+
			"that took the interface's single endpoint slot, which is the ACTUAL "+
			"reason this complete unit endpoint went unemitted (#6861 F1): %q", got)
	}
	if !strings.Contains(got, "Remove THIS UNIT's `tunnel` stanza") {
		t.Errorf("the advisory does not offer the remediation that actually drops "+
			"this dead anchor (#6861 F1): %q", got)
	}
	// #6861 F4: completing the endpoints is INEFFECTIVE here, and the advisory
	// must say so rather than leaving it as an implied option.
	if !strings.Contains(got, "does NOT make it emit") {
		t.Errorf("the advisory leaves \"just complete the endpoints\" open as an "+
			"apparent remedy; under interface-level WireGuard it cannot work "+
			"(#6861 F4): %q", got)
	}
	// The advisory must still carry what it always did: the anchor device name
	// and the #4785 reference.
	if !strings.Contains(got, `"wg0u3"`) || !strings.Contains(got, "#4785") {
		t.Errorf("the advisory lost the anchor device name or the issue "+
			"reference: %q", got)
	}
}

// TestIpipIncompleteUnitStillNamesTheMissingHalf_6861 pins the PRECEDENCE the
// isUnit branch must not disturb. A unit record that is ALSO incomplete has two
// true causes at once; the missing half is the one to report, because it keeps
// the endpoint unemitted even if the interface-level stanza went away.
//
// Stays GREEN under the revert — the incomplete branch is unchanged by this
// fold, and that is exactly what this asserts.
func TestIpipIncompleteUnitStillNamesTheMissingHalf_6861(t *testing.T) {
	// Same two-unit shape as the slot-cause test: unit 1 owns the emitted
	// endpoint's device, so unit 3's `wg0u3` really is dead.
	cfg, err := CompileConfig(ipipTree(t, append(ipipWgIfaceStanza(),
		"set interfaces wg0 unit 1 family inet address 10.1.1.1/30",
		"set interfaces wg0 unit 3 tunnel mode ipip",
		"set interfaces wg0 unit 3 tunnel source 10.0.0.1",
	)...))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	warns := ipipAnchorOnlyWarnings(cfg)
	if len(warns) != 1 {
		t.Fatalf("expected exactly 1 anchor advisory, got %d: %v", len(warns), warns)
	}
	if !strings.Contains(warns[0], "no `tunnel destination` is configured") {
		t.Errorf("an incomplete unit endpoint must still report the MISSING HALF, "+
			"which outlives the slot cause: %q", warns[0])
	}
	if strings.Contains(warns[0], "takes the") {
		t.Errorf("the slot cause displaced the missing-half cause; the incomplete "+
			"check must stay FIRST: %q", warns[0])
	}
}

// ipipRethMemberShape is the #6861 F1 fixture: an emitted `reth0` tunnel
// endpoint whose device is the PHYSICAL MEMBER `ge-0-0-0`, plus a separate
// unemitted ipip record on that member whose anchor device is that same
// `ge-0-0-0`.
//
// The member's ipip record is unemitted because its unit overrides it, so it is
// exactly the kind of record the anchor advisory inspects — and its device is
// carrying reth0's working GRE tunnel.
func ipipRethMemberShape() []string {
	return []string{
		"set chassis cluster redundancy-group 1 node 0 priority 100",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set interfaces ge-0/0/0 tunnel mode ipip",
		"set interfaces ge-0/0/0 tunnel source 10.5.5.1",
		"set interfaces ge-0/0/0 tunnel destination 10.5.5.2",
		"set interfaces ge-0/0/0 unit 1 tunnel mode gre",
		"set interfaces ge-0/0/0 unit 1 tunnel source 10.5.5.1",
		"set interfaces ge-0/0/0 unit 1 tunnel destination 10.5.5.3",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 tunnel mode gre",
		"set interfaces reth0 tunnel source 10.0.0.1",
		"set interfaces reth0 tunnel destination 10.0.0.2",
	}
}

// TestIpipBareRefResolvesLikeTheSnapshot_6861 is the fail-on-revert guard for
// #6861 F1: the BARE-interface arm of the device derivation must be
// snapshotLinuxName's bare arm, not `LinuxIfName(ref)`.
//
// snapshotLinuxName resolves a `reth*` interface through ResolveReth to its
// physical member (pkg/dataplane/userspace/interfaces.go), so an emitted `reth0`
// endpoint occupies device `ge-0-0-0`. `LinuxIfName("reth0")` returns "reth0"
// instead — a device nothing binds — so `ge-0-0-0` is missing from the live set
// and the member's own unemitted ipip anchor, which sits on that device, is
// reported as carrying no traffic. That is a false alarm against the device
// reth0's tunnel is running on: the same defect class as the rest of this PR,
// surviving in the fallback arm.
//
// RED-on-revert: restore `LinuxIfName(ep.Name)` for the bare arm and this fails
// at "declared DEAD ... but that device carries the emitted reth0 endpoint".
func TestIpipBareRefResolvesLikeTheSnapshot_6861(t *testing.T) {
	cfg, err := CompileConfigLenient(ipipTree(t, ipipRethMemberShape()...))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// PRECONDITIONS. reth0 must really emit, its device must really be the
	// member, and the member's ipip record must really sit on that device.
	var rethDevice string
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		if ep.Name == "reth0" {
			rethDevice = cfg.ResolveKernelIfName(ep.Name)
		}
	}
	if rethDevice != "ge-0-0-0" {
		t.Fatalf("fixture precondition: the emitted reth0 endpoint must resolve to "+
			"the physical member device \"ge-0-0-0\" (that is what makes the bare arm "+
			"observably different from LinuxIfName); got %q", rethDevice)
	}
	member := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if member == nil || member.Tunnel == nil || member.Tunnel.Mode != "ipip" ||
		member.Tunnel.Name != "ge-0-0-0" {
		t.Fatalf("fixture precondition: the member must carry an ipip record whose "+
			"anchor device is the same \"ge-0-0-0\": %+v", member)
	}

	var warns []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "kernel anchor device") && strings.Contains(w, "ge-0-0-0\"") {
			warns = append(warns, w)
		}
	}
	if len(warns) != 0 {
		t.Errorf("device \"ge-0-0-0\" was declared DEAD but that device carries the "+
			"emitted reth0 endpoint — the bare-interface arm must resolve a reth "+
			"name through ResolveReth exactly as snapshotLinuxName does, or the live "+
			"set misses the member device entirely (#6861 F1): %v", warns)
	}
}

// TestIpipDottedInterfaceNameResolvesToItsOwnDevice_6861 binds #6861 F3 at the
// DERIVATION, and is explicit that it is not an end-to-end guard.
//
// `ip-0/0/0.0` is a legal AUTHORED interface name, and both it and unit 0 of
// `ip-0/0/0` are emitted under the identical ref "ip-0/0/0.0". Keying the device
// lookup on that string made the bare interface consume the UNIT's TunnelNameMap
// entry, so the bare interface's own device "ip-0-0-0.0" never entered the live
// set at all. The structural walk resolves each emitted ref from the (interface,
// unit) pair it came from, so both devices are recorded.
//
// HONEST SCOPE — read before trusting this as a fail-on-revert guard. Reverting
// to the ref-keyed lookup does NOT change any advisory, and no fixture makes it
// do so. The record whose device was being stolen is itself EMITTED, and
// ipipAnchorOnlyWarnings skips every emitted record on pointer identity before
// the device set is consulted. So the string-keying defect is currently
// unreachable end to end; what is asserted here is the derivation's own output,
// which does differ. Reverting the structural walk fails THIS test and nothing
// else — that is the honest extent of the binding, and it is recorded rather
// than dressed up as behavioural coverage.
func TestIpipDottedInterfaceNameResolvesToItsOwnDevice_6861(t *testing.T) {
	cfg, err := CompileConfigLenient(ipipTree(t,
		"set interfaces ip-0/0/0 unit 0 tunnel mode gre",
		"set interfaces ip-0/0/0 unit 0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 unit 0 tunnel destination 10.0.0.2",
		"set interfaces ip-0/0/0.0 tunnel source 10.9.9.1",
		"set interfaces ip-0/0/0.0 tunnel destination 10.9.9.2",
	))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// PRECONDITION: the collision must actually exist — two DIFFERENT records
	// emitted under one ref, carrying two DIFFERENT devices.
	var devices []string
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		if ep.Name != "ip-0/0/0.0" {
			t.Fatalf("fixture precondition: both records must emit under the single "+
				"colliding ref \"ip-0/0/0.0\"; got %q", ep.Name)
		}
		devices = append(devices, ep.Tunnel.Name)
	}
	if len(devices) != 2 {
		t.Fatalf("fixture precondition: expected 2 endpoints colliding on one ref, "+
			"got %d (%v)", len(devices), devices)
	}

	live := emittedTunnelDeviceNames(cfg)
	for _, want := range []string{"ip-0-0-0", "ip-0-0-0.0"} {
		if !live[want] {
			t.Errorf("device %q is missing from the live set. Both an authored "+
				"interface named \"ip-0/0/0.0\" and unit 0 of \"ip-0/0/0\" emit under "+
				"that one ref, so a lookup keyed on the ref STRING records only "+
				"whichever the map happens to hold and silently drops the other. "+
				"Resolution must come from the (interface, unit) pair (#6861 F3). "+
				"live=%v", want, live)
		}
	}
}

// TestIpipWireguardSlotRemediationIsAchievable_6861 is the fail-on-revert guard
// for #6861 F4: an INCOMPLETE unit under an interface-level WireGuard stanza was
// told to "configure both endpoints (and use mode gre or mode wireguard…)".
// That is factually ineffective — the emitter publishes only the LOWEST unit and
// continues past every other per-unit record — so an operator who complies gets
// the same dead anchor and no endpoint.
//
// RED-on-revert: restore the shared incomplete-branch text and this fails at
// "still recommends completing the endpoints".
func TestIpipWireguardSlotRemediationIsAchievable_6861(t *testing.T) {
	incomplete := append(ipipWgIfaceStanza(),
		"set interfaces wg0 unit 1 family inet address 10.1.1.1/30",
		"set interfaces wg0 unit 3 tunnel mode ipip",
		"set interfaces wg0 unit 3 tunnel source 10.0.0.1",
	)
	cfg, err := CompileConfig(ipipTree(t, incomplete...))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	warns := ipipAnchorOnlyWarnings(cfg)
	if len(warns) != 1 {
		t.Fatalf("expected exactly 1 anchor advisory, got %d: %v", len(warns), warns)
	}
	got := warns[0]

	// The missing half is still the reported CAUSE — that part was correct.
	if !strings.Contains(got, "no `tunnel destination` is configured") {
		t.Errorf("the incomplete cause was lost: %q", got)
	}
	if !strings.Contains(got, "does NOT make it emit") {
		t.Errorf("the advisory still recommends completing the endpoints as though "+
			"that would help; under interface-level WireGuard the unit can never be "+
			"emitted no matter how it is completed (#6861 F4): %q", got)
	}

	// THE PROOF. Follow the old advice to the letter — complete BOTH endpoints
	// AND switch to `mode gre`, the two things it recommended — and show the
	// unit still emits nothing.
	followed := append(ipipWgIfaceStanza(),
		"set interfaces wg0 unit 1 family inet address 10.1.1.1/30",
		"set interfaces wg0 unit 3 tunnel mode gre",
		"set interfaces wg0 unit 3 tunnel source 10.0.0.1",
		"set interfaces wg0 unit 3 tunnel destination 10.0.0.2",
	)
	fixed, err := CompileConfig(ipipTree(t, followed...))
	if err != nil {
		t.Fatalf("compile after following the advice: %v", err)
	}
	for _, ep := range EmitTunnelEndpointNames(fixed) {
		if ep.Name == "wg0.3" {
			t.Fatalf("this test's premise is stale: after completing the endpoints and "+
				"switching to gre, unit 3 DID emit (%+v). The old advice would then "+
				"have been effective and the assertion above is measuring nothing — "+
				"re-derive before trusting it", ep)
		}
	}
}

// TestIpipEmittedRecordIsNeverAlsoAnAnchor_6861 binds the EMITTED-POINTER
// clause of the anchor predicate (#6861 r5).
//
// The device clause alone is not sufficient. An interface whose endpoint IS
// emitted can still have a device name that differs from where that endpoint
// binds: snapshotLinuxName resolves a bare `reth*` through ResolveReth, so
// `reth0`'s endpoint occupies the physical member `ge-0-0-0` while the record's
// own anchor name stays `reth0`. On the device test alone `reth0` is absent from
// the live set and gets reported as a dead anchor — a SECOND diagnosis of a
// record the dead-endpoint advisory already covers correctly, carrying the
// cause "every unit overrides it" on an interface that has no units at all,
// which sends the operator to a stanza that does not exist.
//
// This is the test the r4 comment asserted the need for without measuring; the
// clause was unbound at this site until now.
//
// The orphan `reth0` device is real but is NOT this gate's subject — the same
// orphan appears under `mode gre` where #4785 is deliberately silent, so #4785
// is not its cause. It is tracked as the routing-vs-dataplane name divergence
// in #6941.
//
// RED-on-revert: drop `!emitted[t] &&` from the interface predicate and this
// fails at "was reported as a DEAD ANCHOR even though its endpoint is emitted".
func TestIpipEmittedRecordIsNeverAlsoAnAnchor_6861(t *testing.T) {
	cfg, err := CompileConfigLenient(ipipTree(t,
		"set chassis cluster redundancy-group 1 node 0 priority 100",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 tunnel mode ipip",
		"set interfaces reth0 tunnel source 10.0.0.1",
		"set interfaces reth0 tunnel destination 10.0.0.2",
	))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}

	// PRECONDITIONS. The record must be EMITTED, and its own anchor name must
	// genuinely differ from the device its endpoint binds to — without that
	// divergence the device clause would cover it and this test would prove
	// nothing about the pointer clause.
	eps := EmitTunnelEndpointNames(cfg)
	if len(eps) != 1 || eps[0].Name != "reth0" {
		t.Fatalf("fixture precondition: expected exactly the emitted \"reth0\" "+
			"endpoint, got %d: %+v", len(eps), eps)
	}
	record := cfg.Interfaces.Interfaces["reth0"].Tunnel
	if eps[0].Tunnel != record {
		t.Fatalf("fixture precondition: the emitted endpoint must carry the very " +
			"record under test, else the pointer clause is not what suppresses it")
	}
	device := cfg.ResolveKernelIfName("reth0")
	if device != "ge-0-0-0" || record.Name != "reth0" {
		t.Fatalf("fixture precondition: the record's anchor name (%q) must DIFFER "+
			"from the device its endpoint binds to (%q); with no divergence the "+
			"device clause alone would suppress it and this test would be vacuous",
			record.Name, device)
	}
	if emittedTunnelDeviceNames(cfg)[record.Name] {
		t.Fatalf("fixture precondition: %q must be ABSENT from the live set — that "+
			"absence is precisely what the device clause would trip on", record.Name)
	}

	// The dead-endpoint advisory MUST fire: this record is genuinely a dead IPIP
	// endpoint and the operator has to hear about it exactly once.
	var deadEndpoint, anchor []string
	for _, w := range ValidateConfig(cfg) {
		switch {
		case strings.Contains(w, "kernel anchor device"):
			anchor = append(anchor, w)
		case strings.Contains(w, "tunnel endpoint \"reth0\" has mode ipip"):
			deadEndpoint = append(deadEndpoint, w)
		}
	}
	if len(deadEndpoint) != 1 {
		t.Fatalf("the dead-endpoint advisory must report this record exactly once "+
			"(it IS an emitted ipip endpoint); got %d: %v", len(deadEndpoint), deadEndpoint)
	}
	if len(anchor) != 0 {
		t.Errorf("the record was reported as a DEAD ANCHOR even though its endpoint "+
			"is emitted — a second diagnosis of one record, and its cause is "+
			"structurally false (it blames units on an interface that has none). An "+
			"emitted record belongs to the strict gate and the dead-endpoint "+
			"advisory; the anchor advisory is for records with NO emitted endpoint "+
			"(#6861 r5): %v", anchor)
	}
}

// TestIpipUnitDeviceMatchesTheSnapshotOrdering_6861 binds the unit-arm
// derivation ORDER (#6861 r5).
//
// ResolveKernelIfName is the right derivation but answers XFRM (`st<N>`) and IRB
// refs BEFORE consulting the tunnel map, while snapshotLinuxName — which fills
// the InterfaceSnapshot.LinuxName the dataplane actually binds — consults
// TunnelNameMap first and has no XFRM or IRB arm at all. Deferring to
// ResolveKernelIfName unconditionally therefore recorded a device the dataplane
// never opens and omitted the real one, for exactly the refs where the two
// disagree.
//
// RED-on-revert: drop the TunnelNameMap-first lookup from the unit arm and both
// cases fail at "resolved to ... which is not the device the dataplane binds".
func TestIpipUnitDeviceMatchesTheSnapshotOrdering_6861(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cmds       []string
		ref        string
		wantDevice string // what snapshotLinuxName yields: TunnelNameMap first
		viaResolve string // what ResolveKernelIfName yields, taking its own arm first
	}{
		{
			name: "xfrm_st_unit",
			cmds: []string{
				"set interfaces st0 unit 1 tunnel mode ipip",
				"set interfaces st0 unit 1 tunnel source 10.0.0.1",
				"set interfaces st0 unit 1 tunnel destination 10.0.0.2",
			},
			ref: "st0.1", wantDevice: "st0u1", viaResolve: "st0.1",
		},
		{
			name: "irb_unit_under_a_bridge_domain",
			cmds: []string{
				"set bridge-domains bd0 vlan-id 10",
				"set bridge-domains bd0 routing-interface irb.0",
				"set interfaces irb unit 0 tunnel mode ipip",
				"set interfaces irb unit 0 tunnel source 10.0.0.1",
				"set interfaces irb unit 0 tunnel destination 10.0.0.2",
			},
			ref: "irb.0", wantDevice: "irb", viaResolve: "br-bd0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(ipipTree(t, tc.cmds...))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			// PRECONDITIONS: the ref must be emitted, and the two derivations
			// must genuinely disagree — otherwise the ordering is unobservable
			// and this case proves nothing.
			eps := EmitTunnelEndpointNames(cfg)
			if len(eps) != 1 || eps[0].Name != tc.ref {
				t.Fatalf("fixture precondition: expected the single emitted ref %q, "+
					"got %d: %+v", tc.ref, len(eps), eps)
			}
			if got := cfg.TunnelNameMap()[tc.ref]; got != tc.wantDevice {
				t.Fatalf("fixture precondition: TunnelNameMap must yield %q for %q "+
					"(that is snapshotLinuxName's answer); got %q",
					tc.wantDevice, tc.ref, got)
			}
			if got := cfg.ResolveKernelIfName(tc.ref); got != tc.viaResolve {
				t.Fatalf("fixture precondition: the two derivations must DISAGREE for "+
					"this ref, else the ordering is unobservable — ResolveKernelIfName "+
					"was expected to yield %q, got %q", tc.viaResolve, got)
			}

			live := emittedTunnelDeviceNames(cfg)
			if !live[tc.wantDevice] {
				t.Errorf("the emitted endpoint %q resolved to a device the dataplane "+
					"never binds: the live set is %v but snapshotLinuxName binds this "+
					"endpoint to %q. The unit arm must consult TunnelNameMap FIRST, as "+
					"snapshotLinuxName does (#6861 r5)", tc.ref, live, tc.wantDevice)
			}
			if live[tc.viaResolve] {
				t.Errorf("the live set contains %q, which is ResolveKernelIfName's "+
					"answer taken from an arm snapshotLinuxName does not have. A device "+
					"nothing binds must not mark anything live: %v", tc.viaResolve, live)
			}
		})
	}
}

// TestIpipAnchorEmittedClauseIsPointerKeyedNotNameKeyed_6861 binds the KEYING
// of the interface site's emitted clause, which its sibling above does not.
//
// The distinction matters because the two tests fail to different mutations.
// TestIpipEmittedRecordIsNeverAlsoAnAnchor_6861 reds when `!emitted[t]` is
// DELETED — it proves an emitted-check exists. It stays GREEN when the check is
// re-keyed from the pointer to `t.Name`, because in its fixture the emitted
// record IS the record under test, so both keyings agree. Existence and keying
// are separate properties and need separate fixtures.
//
// The discriminator needs an emitted record that is NOT `t` yet shares `t.Name`,
// with `t.Name` absent from the live device set so the device clause cannot be
// what decides. Two TunnelConfig records share a Name only via:
//
//   - an interface-level record and its own unit 0 (both `LinuxIfName(ifName)`)
//     — but TunnelNameMap resolves that unit ref to exactly that name, so the
//     device clause suppresses it first and the keying never decides; or
//   - two DIFFERENT interface keys collapsing to one Linux name, since
//     LinuxIfName only replaces '/' with '-'. `gr-0/0-0` is a one-character slip
//     from `gr-0/0/0` and both canonicalize to `gr-0-0-0`.
//
// The second is this fixture, combined with the one shape whose emitted device
// diverges from its record's Name: interface-level WireGuard whose lowest unit
// is > 0. The emitter publishes the INTERFACE pointer at ref `gr-0/0/0.1`
// (#1910) while TunnelNameMap resolves that ref to the UNIT device
// `gr-0-0-0u1`, so `gr-0-0-0` is emitted-by-name but absent from `live`.
//
// SCOPE, stated plainly: a strict commit REJECTS this config — the duplicate
// Linux-device-name gate fires on `gr-0/0-0` vs `gr-0/0/0`. So on any config
// that can be committed the two keyings are equivalent, and the pointer clause
// buys nothing there. It is load-bearing on the TOLERANT surface instead
// (#1960): configstore's Load/SyncApply lenient-compiles a config a strict
// commit would refuse, and `show system` renders ValidateConfig's warnings for
// whatever is active. On that path name-keying silently drops a real dead ipip
// anchor because an unrelated interface happens to canonicalize to the same
// device name. Pointer keying is correct without depending on another gate
// staying in place, which is why it is kept.
//
// WHAT THIS FIXTURE ESTABLISHES, exactly (#6861 re-gate B2). It proves IDENTITY
// SEMANTICS versus NAME KEYING: there is one emitted reference, its record is a
// DIFFERENT object from the candidate, the two Names are equal, and that Name is
// absent from the live device set — so a name-keyed set suppresses a warning
// that an identity-keyed one raises. It does NOT prove that a literal Go pointer
// is the only implementation; any keying on record identity would do, and
// deleting the emitted clause outright still produces the warning (its sibling
// TestIpipEmittedRecordIsNeverAlsoAnAnchor_6861 is what catches that deletion,
// deliberately — existence and keying are separate properties).
//
// AND ITS RENDERED REMEDIATION IS NOT ACCURATE FOR THIS SHAPE. The advisory
// tells the operator that removing the interface-level `tunnel` stanza would
// drop the anchor. Here it would not: collectAppliedTunnels submits both the
// unrelated interface WireGuard record and this IPIP record under the same base
// device, routing reconciles every record, so the WireGuard record retains or
// recreates that TUN. The device is SHARED, not uniquely created by the IPIP
// site. The wording is written for the committable single-owner case and this
// fixture is reachable only on the tolerant surface; it is recorded here rather
// than rewritten because the assertion under test is the KEYING, and narrowing
// the shared production text for a tolerant-only shape is a separate change.
//
// RED-on-revert: re-key the clause to a name-keyed set
// (`!emittedName[t.Name]`, built from the same EmitTunnelEndpointNames walk)
// and this fails at "the anchor advisory did not fire".
func TestIpipAnchorEmittedClauseIsPointerKeyedNotNameKeyed_6861(t *testing.T) {
	cfg, err := CompileConfigLenient(ipipTree(t,
		// Emitted, and its device DIVERGES from its record's Name: the
		// emitted endpoint is keyed to unit 1 and resolves to unit 1's
		// device (gr-0-0-0u1), while the record it carries is the
		// interface-level object named gr-0-0-0. That divergence is this
		// test's LEVER — it is what makes name-keying and device-keying
		// disagree, and without it the device clause decides first and the
		// keying under test is never consulted.
		//
		// The unit is `mode gre` rather than `mode wireguard` (#6941). A unit
		// that stays on the interface's WireGuard mode now SHARES the
		// interface device, because an interface-level WireGuard interface has
		// exactly one endpoint and so at most one device that can carry it;
		// with `mode wireguard` here the device set would contain gr-0-0-0 and
		// the precondition below would fail. A mode-overriding unit keeps its
		// own uN device (routing keys its desired set by Name, and sharing a
		// name across two different MODES would be a conflict), so it still
		// produces the divergence this fixture needs.
		"set interfaces gr-0/0/0 tunnel mode wireguard",
		"set interfaces gr-0/0/0 unit 1 tunnel mode gre",
		// The anchor candidate: same canonical Linux name, ipip, source but no
		// destination so the emitter skips it entirely.
		"set interfaces gr-0/0-0 tunnel mode ipip",
		"set interfaces gr-0/0-0 tunnel source 10.0.0.1",
	))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}

	// PRECONDITIONS. Each one is a way this fixture could silently stop
	// discriminating, which would leave the test green while proving nothing.
	cand := cfg.Interfaces.Interfaces["gr-0/0-0"]
	if cand == nil || cand.Tunnel == nil {
		t.Fatalf("fixture precondition: the candidate interface must survive the " +
			"tolerant compile with its tunnel record")
	}
	rec := cand.Tunnel
	if rec.Mode != "ipip" || rec.Source == "" || rec.Destination != "" {
		t.Fatalf("fixture precondition: candidate must be ipip with a source and no "+
			"destination (mode=%q src=%q dst=%q)", rec.Mode, rec.Source, rec.Destination)
	}
	eps := EmitTunnelEndpointNames(cfg)
	if len(eps) != 1 || eps[0].Name != "gr-0/0/0.1" {
		t.Fatalf("fixture precondition: expected exactly the emitted \"gr-0/0/0.1\" "+
			"endpoint, got %d: %+v", len(eps), eps)
	}
	// FORWARD ASSERT, not a reachable branch (#6861 re-gate T3). Once the check
	// above has pinned the sole emitted ref to "gr-0/0/0.1", its record is by
	// construction the tunnel of a DIFFERENT interface than `gr-0/0-0`, so this
	// can no longer fail. It is kept deliberately: it states the property the
	// discriminator depends on at the point a future fixture edit would break
	// it, and such an edit would land here before it landed on the assertion.
	if eps[0].Tunnel == rec {
		t.Fatalf("fixture precondition: the emitted record must be a DIFFERENT object " +
			"from the candidate, else pointer and name keying cannot disagree")
	}
	if eps[0].Tunnel.Name != rec.Name {
		t.Fatalf("fixture precondition: the emitted record's Name (%q) must EQUAL the "+
			"candidate's (%q) — that collision is the whole discriminator",
			eps[0].Tunnel.Name, rec.Name)
	}
	if emittedTunnelDeviceNames(cfg)[rec.Name] {
		t.Fatalf("fixture precondition: %q must be ABSENT from the live device set, "+
			"otherwise the device clause decides and the keying is never consulted",
			rec.Name)
	}

	// The candidate must carry NO units. Without this the matcher below can go
	// vacuous (#6861 re-gate T1): a unit added by fixture or compiler drift
	// would emit its OWN anchor warning under the same `interfaces "gr-0/0-0"`
	// substring, so name keying could suppress the INTERFACE warning this test
	// is about while len(anchor)==1 stayed green on the unit's.
	if len(cand.Units) != 0 {
		t.Fatalf("fixture precondition: the candidate must have NO units (has %d) — a "+
			"unit contributes its own anchor warning matching the same substring, which "+
			"would let this test pass on the wrong warning", len(cand.Units))
	}

	// The candidate is a genuine dead ipip anchor and the operator must hear
	// about it. Under name keying the unrelated WireGuard record's Name
	// suppresses this warning entirely.
	var anchor []string
	for _, w := range ValidateConfig(cfg) {
		// The EXACT interface-site prefix, not merely the interface name: a unit
		// warning renders `interfaces "gr-0/0-0" unit N tunnel mode ipip:` and
		// would satisfy a substring match on the name alone.
		if strings.Contains(w, "kernel anchor device") &&
			strings.HasPrefix(w, `interfaces "gr-0/0-0" tunnel mode ipip:`) {
			anchor = append(anchor, w)
		}
	}
	if len(anchor) != 1 {
		t.Fatalf("the anchor advisory did not fire exactly once for the unemitted "+
			"ipip record on \"gr-0/0-0\" (got %d). Its own endpoint is NOT emitted, so "+
			"it creates a kernel anchor carrying nothing; a name-keyed emitted set "+
			"suppresses it because a DIFFERENT interface (\"gr-0/0/0\") canonicalizes "+
			"to the same device name %q: %v", len(anchor), rec.Name, anchor)
	}
}

// TestIpipAnchorIgnoresAnEndpointTheRuntimeDrops_6861 binds the ID-COLLISION
// arm of the live set (#6861 re-gate B1).
//
// THE DEFECT. `emittedTunnelDeviceNames` recorded every EMITTED endpoint
// reference as live. Being emitted is necessary but not sufficient: the builder
// (buildTunnelEndpointSnapshots) hashes each ref to a StableTunnelEndpointID
// and appends NOTHING when the id is already taken, so the later-sorting
// collider never becomes an endpoint. Counting it live suppressed the anchor
// advisory for a device that genuinely carries no traffic — the exact inverse
// of what this advisory exists to report, and the operator gets SILENCE.
//
// WHY THE TOLERANT PATH IS THE WHOLE POINT. `validateTunnelEndpointIDCollisionAST`
// rejects this config at strict commit, so an operator typing it is stopped.
// The tolerant ingress is not: Store.Load at boot and Store.SyncApply from a
// peer keep it (#1960 no-brick), and `show system alarms` recomputes
// ValidateConfig — which is the surface asserted here.
//
// THE FIXTURE IS NOT HAND-PICKED. `wg0` and `wg34524.0` are the collision pair
// already frozen by TestTunnelEndpointIDOverflowOnlyUnitHashesBareRef
// (tunnelid_test.go), so this test cannot silently stop colliding: the
// precondition below re-asserts the fold, and if StableTunnelEndpointID ever
// changes, that test fails too rather than this one going vacuously green.
func TestIpipAnchorIgnoresAnEndpointTheRuntimeDrops_6861(t *testing.T) {
	if a, b := StableTunnelEndpointID("wg0"), StableTunnelEndpointID("wg34524.0"); a != b || a != 17799 {
		t.Fatalf("precondition: wg0=%d wg34524.0=%d, want both 17799 — this fixture is "+
			"only a collision because those two refs fold together (tunnelid_test.go)", a, b)
	}
	cmds := []string{
		// Complete GRE on wg0 with NO units: emits the bare ref "wg0", which
		// sorts first and therefore CLAIMS id 17799 at the builder.
		"set interfaces wg0 tunnel mode gre",
		"set interfaces wg0 tunnel source 10.0.0.1",
		"set interfaces wg0 tunnel destination 10.0.0.2",
		// The subject: an interface-level IPIP anchor whose unit 0 overrides it
		// with a complete GRE. The emitter publishes the UNIT's pointer as
		// "wg34524.0" — which collides and is dropped — while the interface's
		// own IPIP record still creates the "wg34524" kernel device.
		"set interfaces wg34524 tunnel mode ipip",
		"set interfaces wg34524 tunnel source 10.0.1.1",
		"set interfaces wg34524 unit 0 tunnel mode gre",
		"set interfaces wg34524 unit 0 tunnel source 10.0.1.1",
		"set interfaces wg34524 unit 0 tunnel destination 10.0.1.2",
	}
	tree := ipipTree(t, cmds...)

	// Strict commit must still REJECT — the collision gate owns that, and if it
	// ever stopped firing this fixture would be reachable by an ordinary commit
	// and the test would be about a different thing.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict commit ACCEPTED a tunnel-endpoint id collision; this fixture is " +
			"supposed to be reachable only through the tolerant ingress")
	} else if !strings.Contains(err.Error(), "collision") {
		t.Fatalf("strict rejection is not the collision gate: %v", err)
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile must keep this config (#1960 no-brick): %v", err)
	}

	// PRECONDITION, so the assertion below cannot pass for the wrong reason:
	// BOTH refs are emitted and they DO collide. Without this, a fixture that
	// stopped emitting the unit ref would make the advisory fire trivially.
	var refs []string
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		refs = append(refs, ep.Name)
	}
	if len(refs) != 2 || refs[0] != "wg0" || refs[1] != "wg34524.0" {
		t.Fatalf("emitted refs = %q, want exactly [wg0 wg34524.0] in that order — the "+
			"builder keeps the FIRST and drops the second, so the order is load-bearing", refs)
	}

	// The live set must NOT contain the dropped endpoint's device.
	live := emittedTunnelDeviceNames(cfg)
	if !live["wg0"] {
		t.Fatal(`live set lost "wg0" — the collision WINNER must stay live`)
	}
	if live["wg34524"] {
		t.Fatal(`live set contains "wg34524", whose only emitted endpoint ("wg34524.0") ` +
			`the builder DROPS on the id collision — an endpoint the runtime never ` +
			`creates must not count as live, or the anchor advisory is suppressed for a ` +
			`device that carries nothing (#6861 B1)`)
	}

	// And the advisory must reach the real alarm surface, naming the anchor.
	var ipipWarns []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "ipip") {
			ipipWarns = append(ipipWarns, w)
		}
	}
	if len(ipipWarns) != 1 {
		t.Fatalf("ValidateConfig produced %d ipip warning(s), want exactly 1:\n%s",
			len(ipipWarns), strings.Join(ipipWarns, "\n"))
	}
	if !strings.HasPrefix(ipipWarns[0], `interfaces "wg34524" tunnel mode ipip:`) {
		t.Fatalf("the ipip warning is not the wg34524 interface anchor: %s", ipipWarns[0])
	}
}

// TestIpipAnchorCollisionDropDoesNotOverreach_6861 is the negative control for
// the drop above: the SAME two interfaces, renamed so their ids no longer
// collide, must produce NO anchor advisory at all.
//
// Without this, a mutation that dropped every emitted ref from the live set —
// or simply broke the id computation so nothing ever matched — would leave the
// test above green while manufacturing a false "this device is dead" against a
// perfectly live GRE endpoint, which is the failure direction this advisory
// must never take.
func TestIpipAnchorCollisionDropDoesNotOverreach_6861(t *testing.T) {
	cmds := []string{
		"set interfaces wg0 tunnel mode gre",
		"set interfaces wg0 tunnel source 10.0.0.1",
		"set interfaces wg0 tunnel destination 10.0.0.2",
		// wg1 instead of wg34524: same shape, no id collision.
		"set interfaces wg1 tunnel mode ipip",
		"set interfaces wg1 tunnel source 10.0.1.1",
		"set interfaces wg1 unit 0 tunnel mode gre",
		"set interfaces wg1 unit 0 tunnel source 10.0.1.1",
		"set interfaces wg1 unit 0 tunnel destination 10.0.1.2",
	}
	cfg, err := CompileConfig(ipipTree(t, cmds...))
	if err != nil {
		t.Fatalf("the non-colliding twin must COMMIT: %v", err)
	}
	if a, b := StableTunnelEndpointID("wg0"), StableTunnelEndpointID("wg1.0"); a == b {
		t.Fatalf("control fixture collides after all (both %d); pick another name", a)
	}
	live := emittedTunnelDeviceNames(cfg)
	if !live["wg0"] || !live["wg1"] {
		t.Fatalf("both devices must be live with no collision, got %v", live)
	}
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "ipip") {
			t.Fatalf("no-collision twin raised an ipip advisory against a live GRE "+
				"endpoint: %s", w)
		}
	}
}
