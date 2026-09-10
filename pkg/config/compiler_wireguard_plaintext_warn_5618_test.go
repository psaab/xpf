package config

import (
	"fmt"
	"strings"
	"testing"
)

// wgTunnel5618 renders the minimum set of `set` lines that make an interface a
// VALID WireGuard tunnel. validateWireguardPeersStrict hard-rejects a tunnel
// missing a listen-port, private-key or peer (#1434/#3863), so every test that
// drives CompileConfig has to author all three — otherwise the compile would
// fail for a reason that has nothing to do with #5618 and the no-brick
// assertion below would be meaningless.
func wgTunnel5618(iface string, unit int, port int, priv, peer string) []string {
	stanza := fmt.Sprintf("set interfaces %s", iface)
	if unit >= 0 {
		stanza = fmt.Sprintf("set interfaces %s unit %d", iface, unit)
	}
	return []string{
		stanza + " tunnel mode wireguard",
		fmt.Sprintf("%s tunnel wireguard listen-port %d", stanza, port),
		stanza + " tunnel wireguard private-key " + priv,
		stanza + " tunnel wireguard peer " + peer + " allowed-ips 10.77.0.0/16",
	}
}

func compileWarn5618(t *testing.T, lines ...string) *Config {
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
		t.Fatalf("CompileConfig: %v (a #5618 plaintext advisory must NEVER reject)", err)
	}
	return cfg
}

func plaintextWarnings5618(cfg *Config) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5618") {
			out = append(out, w)
		}
	}
	return out
}

// TestWGPlaintextWarningScopesTheZoneToTheDataplanePath re-anchors what was
// TestWGPlaintextWarningNamesTheContradictedZone (#9251).
//
// That cell pinned the pre-#8274 escalation: a zoned WireGuard tunnel had been
// "told something specific and untrue", so the advisory had to say "reads as
// protected and is not" and "does NOT govern its decapsulated traffic". #8274
// moved transport decap into the AF_XDP worker, which adjudicates the inner
// packet under the tunnel's zone (worker_decap_presents_inner_under_the_tunnel_
// zone_8274, poll_loop_adjudicates_wg_inner_plaintext_under_the_tunnel_zone_8274)
// — so that escalation became the untrue statement. What the prior decision
// protected survives: exactly ONE advisory, naming the interface and its zone,
// and telling the operator precisely where that zone does NOT reach.
func TestWGPlaintextWarningScopesTheZoneToTheDataplanePath(t *testing.T) {
	lines := wgTunnel5618("wg0", 0, 51820, wgKeyA, wgKeyB)
	lines = append(lines, "set security zones security-zone vpn interfaces wg0.0")
	cfg := compileWarn5618(t, lines...)

	got := plaintextWarnings5618(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 #5618 advisory, got %d: %v", len(got), cfg.Warnings)
	}
	adv := got[0]
	for _, want := range []string{
		"wg0.0",
		`security-zone "vpn"`,
		// The zone governs the dataplane path, and the advisory says so ...
		"which governs its traffic on the dataplane path but NOT on the kernel path",
		// ... names the kernel path's forwarding case (uncovered ingress) ...
		"written straight to the wgN TUN",
		"on an ingress interface the dataplane does not attach to",
		// ... and says a degraded window's arrivals on adjudicated ingress have
		// their transit REFUSED (#9594). Re-anchored by #9594: this cell used to
		// require "while the dataplane is degraded" as one of the ways ONTO the
		// forwarding path, which #9594 made false.
		"While the dataplane is degraded",
		"transit is dropped and counted as a degraded-transit receive drop (#9594)",
		// ... and does not tell a multi-port operator that a refused tunnel leaks.
		"A record for any other listen port is dropped on that path (#9521)",
	} {
		if !strings.Contains(adv, want) {
			t.Errorf("advisory missing %q; got: %s", want, adv)
		}
	}
	// The pre-#8274 account must be GONE. Each of these was once REQUIRED by
	// this cell; each is false for a zone the dataplane enforces.
	for _, stale := range []string{
		"reads as protected and is not",
		"NOT ENFORCED",
		"does NOT govern its decapsulated traffic",
		"decapsulated traffic on WireGuard tunnels is NOT evaluated",
		// The pre-#9594 account, which listed a degraded window as a way onto
		// the TUN write.
		"or while the dataplane is degraded",
	} {
		if strings.Contains(adv, stale) {
			t.Errorf("advisory still carries the pre-#8274 claim %q, false since the "+
				"worker adjudicates WireGuard decap under the tunnel's zone (#8274, "+
				"#9251); got: %s", stale, adv)
		}
	}
	// The zoned tunnel must NOT also be reported as unzoned, and the #6682
	// caveat must not fire when every tunnel carries a zone.
	if strings.Contains(adv, wgPlaintextUnzonedHeading) {
		t.Errorf("the unzoned group must be omitted entirely when empty: %s", adv)
	}
	if strings.Contains(adv, "#6682") {
		t.Errorf("the unzoned caveat fired for a tunnel that IS zoned: %s", adv)
	}
}

// TestWGPlaintextWarningFiresForUnzonedTunnel: the advisory fires whenever a
// WireGuard tunnel is configured, NOT only when one carries a zone.
//
// Leaving the tunnel out of a zone does not close the KERNEL path — the control
// thread's TUN write consults no zone — so gating on zoning would tell exactly
// this operator nothing.
//
// #9251 re-anchored the caveat this cell pins. It used to require the shared
// "An UNZONED tunnel is not safer ... it only leaves it unadjudicated by a
// different route" sentence. That is still true of IPsec, and it is FALSE of
// WireGuard's dataplane path: the policy stage resolves an unzoned tunnel's
// logical ifindex to zone id 0 and #6682 denies transit from it, even under
// `default-policy permit-all` with a both-any permit
// (poll_loop_denies_unzoned_wg_tunnel_transit_under_permit_all_9251). The
// caveat must now state both halves.
//
// (#6682: the older "an interface in no zone resolves to zone id 0 and a
// `from-zone any to-zone any permit` rule matches zone-pair (0,0) with no zone
// guard" claim was wrong — #3110 fenced every tier against zone 0, and #6682
// made an unzoned ingress an explicit deny.)
func TestWGPlaintextWarningFiresForUnzonedTunnel(t *testing.T) {
	cfg := compileWarn5618(t, wgTunnel5618("wg0", 0, 51820, wgKeyA, wgKeyB)...)

	got := plaintextWarnings5618(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 #5618 advisory, got %d: %v", len(got), cfg.Warnings)
	}
	adv := got[0]
	idx := strings.Index(adv, wgPlaintextUnzonedHeading)
	if idx < 0 {
		t.Fatalf("an unzoned WireGuard tunnel must land in the %q group; got: %s",
			wgPlaintextUnzonedHeading, adv)
	}
	if !strings.Contains(adv[idx:], "wg0.0") {
		t.Errorf("the unzoned tunnel must be named in that group: %s", adv)
	}
	if strings.Contains(adv, wgPlaintextZonedHeading) {
		t.Errorf("the zoned group must be omitted entirely when empty: %s", adv)
	}
	for _, want := range []string{
		"DENIED on the dataplane path (#6682)",
		"does not close the kernel path",
	} {
		if !strings.Contains(adv, want) {
			t.Errorf("with an unzoned tunnel present the caveat must state both halves "+
				"(denied on the dataplane path; the kernel path untouched by zoning); "+
				"missing %q in: %s", want, adv)
		}
	}
	if strings.Contains(adv, "unadjudicated by a different route") {
		t.Errorf("the WireGuard advisory rendered IPsec's unzoned caveat, which is false "+
			"on WireGuard's dataplane path (#6682 denies an unzoned ingress): %s", adv)
	}
}

// TestWGPlaintextWarningReadsBracketedZoneList is the #2419/#5248 multi-value
// coverage, and it is the assertion that proves the membership flattener is
// really being used.
//
// `interfaces [ wg0.0 wg1.0 ]` arrives BRACKET-STRIPPED, with wg1.0 nested as a
// CHILD of wg0.0. A reader that took only `iface.Name()` would see wg0.0 alone,
// so wg1.0 would silently fall into the UNZONED group — the advisory would
// still fire, would still be exactly one, and would still name both interfaces,
// yet it would have reported the second tunnel as in no zone. The zone-
// clause COUNT is what separates those two worlds, so that is what is asserted.
func TestWGPlaintextWarningReadsBracketedZoneList(t *testing.T) {
	var lines []string
	lines = append(lines, wgTunnel5618("wg0", 0, 51820, wgKeyA, wgKeyB)...)
	lines = append(lines, wgTunnel5618("wg1", 0, 51821, wgKeyB, wgKeyC)...)
	lines = append(lines, "set security zones security-zone vpn interfaces [ wg0.0 wg1.0 ]")
	cfg := compileWarn5618(t, lines...)

	got := plaintextWarnings5618(cfg)
	if len(got) != 1 {
		t.Fatalf("want ONE aggregated #5618 advisory, got %d: %v", len(got), got)
	}
	adv := got[0]
	for _, ref := range []string{"wg0.0", "wg1.0"} {
		if !strings.Contains(adv, ref+" (interfaces") {
			t.Errorf("advisory does not name %s: %s", ref, adv)
		}
	}
	if n := strings.Count(adv, `security-zone "vpn"`); n != 2 {
		t.Errorf("a bracketed zone member lost its zone clause (%d of 2 present) — the "+
			"tail of `interfaces [ wg0.0 wg1.0 ]` was dropped, so it was reported as "+
			"unzoned: %s", n, adv)
	}
	if strings.Contains(adv, wgPlaintextUnzonedHeading) {
		t.Errorf("both members are zoned, so the unzoned group must be absent: %s", adv)
	}
}

// TestWGPlaintextWarningIsQuietWithoutWireGuard is the negative control. A
// config with no WireGuard tunnel must produce no #5618 advisory at all —
// including one carrying a GRE tunnel, which is decapped INSIDE the worker
// pipeline (userspace-dp/src/afxdp/gre.rs rebinds ingress_ifindex to the
// tunnel's logical_ifindex and derives ingress_zone from
// ifindex_to_zone_id) and therefore IS adjudicated.
//
// This is what pins the advisory to the tunnel MODE rather than to "is a
// tunnel": the GRE interface is Tunnel=true and is excluded from AF_XDP ingress
// binding exactly like a WireGuard one, so a predicate keyed on the exclusion
// flag alone would fire here and be wrong.
func TestWGPlaintextWarningIsQuietWithoutWireGuard(t *testing.T) {
	cfg := compileWarn5618(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.1.1",
		"set interfaces gr-0/0/0 unit 0 tunnel destination 10.0.2.1",
		"set security zones security-zone vpn interfaces gr-0/0/0.0",
	)
	if got := plaintextWarnings5618(cfg); len(got) != 0 {
		t.Errorf("advisory fired with no WireGuard tunnel configured: %v", got)
	}
}

// TestWGPlaintextWarningNeverRejects is the no-brick property (#1960), and it
// is the one this file exists to defend. An operator with a working WireGuard
// tunnel must be able to commit an UNRELATED change. Compiles must succeed in
// every shape, and the advisory must still be present.
func TestWGPlaintextWarningNeverRejects(t *testing.T) {
	ifaceLevel := wgTunnel5618("wg0", -1, 51820, wgKeyA, wgKeyB)

	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"interface_level_tunnel", ifaceLevel},
		{"zoned_tunnel_plus_unrelated_change", append(append([]string{},
			wgTunnel5618("wg0", 0, 51820, wgKeyA, wgKeyB)...),
			"set security zones security-zone vpn interfaces wg0.0",
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
			"set security zones security-zone trust interfaces ge-0/0/0.0",
			"set system host-name fw-unrelated-change",
		)},
		{"several_tunnels", append(append([]string{},
			wgTunnel5618("wg0", 0, 51820, wgKeyA, wgKeyB)...),
			wgTunnel5618("wg1", 0, 51821, wgKeyB, wgKeyC)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileWarn5618(t, tc.lines...)
			if len(plaintextWarnings5618(cfg)) == 0 {
				t.Error("expected at least one #5618 advisory")
			}
		})
	}
}

// TestWGPlaintextWarningIsAggregatedToOne pins the aggregation contract: ONE
// advisory per commit however many WireGuard tunnels are configured. An
// advisory that fires N times on every commit is filtered out, and then it
// protects nobody.
func TestWGPlaintextWarningIsAggregatedToOne(t *testing.T) {
	keys := []string{wgKeyA, wgKeyB, wgKeyC}
	for _, n := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("%d_tunnels", n), func(t *testing.T) {
			var lines []string
			for i := 0; i < n; i++ {
				lines = append(lines, wgTunnel5618(
					fmt.Sprintf("wg%d", i), 0, 51820+i, keys[i], keys[(i+1)%len(keys)])...)
			}
			cfg := compileWarn5618(t, lines...)
			got := plaintextWarnings5618(cfg)
			if len(got) != 1 {
				t.Fatalf("want exactly 1 aggregated advisory for %d tunnels, got %d: %v",
					n, len(got), got)
			}
			for i := 0; i < n; i++ {
				ref := fmt.Sprintf("wg%d.0", i)
				if !strings.Contains(got[0], ref) {
					t.Errorf("the single advisory must name every affected tunnel; %s "+
						"missing from: %s", ref, got[0])
				}
			}
		})
	}
}

// TestWGPlaintextWarningSeparatesZonedFromUnzoned pins the zoned group and the
// unzoned caveat, each for the right tunnel, in ONE advisory. #9251 re-anchored
// both from the IPsec headings to WireGuard's own.
func TestWGPlaintextWarningSeparatesZonedFromUnzoned(t *testing.T) {
	var lines []string
	lines = append(lines, wgTunnel5618("wg0", 0, 51820, wgKeyA, wgKeyB)...)
	lines = append(lines, wgTunnel5618("wg1", 0, 51821, wgKeyB, wgKeyC)...)
	lines = append(lines, "set security zones security-zone vpn interfaces wg0.0")
	cfg := compileWarn5618(t, lines...)

	got := plaintextWarnings5618(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 aggregated advisory, got %d: %v", len(got), got)
	}
	adv := got[0]

	zoneIdx := strings.Index(adv, wgPlaintextZonedHeading)
	plainIdx := strings.Index(adv, wgPlaintextUnzonedHeading)
	if zoneIdx < 0 || plainIdx < 0 {
		t.Fatalf("advisory must carry BOTH groups; got: %s", adv)
	}
	zonedSection := adv[zoneIdx:plainIdx]
	if !strings.Contains(zonedSection, "wg0.0") {
		t.Errorf("the zoned tunnel must be in the zoned group: %s", adv)
	}
	if strings.Contains(zonedSection, "wg1.0") {
		t.Errorf("the UNZONED tunnel must not be reported as zoned: %s", adv)
	}
	if !strings.Contains(adv[plainIdx:], "wg1.0") {
		t.Errorf("the unzoned tunnel must be named: %s", adv)
	}
	if !strings.Contains(adv, "DENIED on the dataplane path (#6682)") {
		t.Errorf("with an unzoned tunnel present the advisory must carry WireGuard's "+
			"unzoned caveat (#6682): %s", adv)
	}
}

// TestWGPlaintextWarningMatchesZoneAcrossSpellings pins the join between the
// tunnel's declaration site and the zone's spelling.
//
// An INTERFACE-level `tunnel mode wireguard` is ONE persistent wgN TUN shared
// by every unit (Config.TunnelNameMap), so a zone on `wg0.0` governs that same
// TUN even though the tunnel is declared on bare `wg0`. Conversely a BARE zone
// member means "every unit of wg0", so it governs a per-unit tunnel on `wg0.0`.
// Reporting either as unzoned would tell the operator the tunnel's transit is
// DENIED on the dataplane path (the unzoned caveat) when that zone in fact
// admits it under policy.
func TestWGPlaintextWarningMatchesZoneAcrossSpellings(t *testing.T) {
	for _, tc := range []struct {
		name    string
		unit    int
		zoneRef string
	}{
		{"unit_tunnel_unit_zone", 0, "wg0.0"},
		{"unit_tunnel_bare_zone", 0, "wg0"},
		{"iface_tunnel_unit_zone", -1, "wg0.0"},
		{"iface_tunnel_bare_zone", -1, "wg0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := wgTunnel5618("wg0", tc.unit, 51820, wgKeyA, wgKeyB)
			lines = append(lines, "set security zones security-zone vpn interfaces "+tc.zoneRef)
			cfg := compileWarn5618(t, lines...)
			got := plaintextWarnings5618(cfg)
			if len(got) != 1 {
				t.Fatalf("want exactly 1 advisory, got %d: %v", len(got), got)
			}
			if !strings.Contains(got[0], wgPlaintextZonedHeading) {
				t.Errorf("a WireGuard tunnel declared at unit=%d with a zone on %q must "+
					"land in the ZONED group — they are the same wgN TUN, and "+
					"reporting it as unzoned would tell the operator its transit is "+
					"denied when that zone admits it. Got: %s",
					tc.unit, tc.zoneRef, got[0])
			}
			if strings.Contains(got[0], "#6682") {
				t.Errorf("the unzoned caveat fired for a tunnel that IS zoned: %s", got[0])
			}
		})
	}
}

// TestWGPlaintextWarningDoesNotFanAZoneSideways is the inverse of the test
// above, and it exists because the fan-out that makes the spellings meet could
// easily be written one step too wide.
//
// Under PER-UNIT tunnels, unit 0 takes the base Linux device and unit N>0 takes
// a `uN` device (compiler_interfaces.go), so `wg0.1` is a DIFFERENT device from
// `wg0.0`. A zone on `wg0.0` must not be reported as governing `wg0.1`:
// claiming a tunnel is zoned when it is not is the same class of untruth this
// advisory exists to correct, just pointed the other way.
func TestWGPlaintextWarningDoesNotFanAZoneSideways(t *testing.T) {
	var lines []string
	lines = append(lines, wgTunnel5618("wg0", 0, 51820, wgKeyA, wgKeyB)...)
	lines = append(lines, wgTunnel5618("wg0", 1, 51821, wgKeyB, wgKeyC)...)
	lines = append(lines, "set security zones security-zone vpn interfaces wg0.0")
	cfg := compileWarn5618(t, lines...)

	got := plaintextWarnings5618(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 advisory, got %d: %v", len(got), got)
	}
	adv := got[0]
	plainIdx := strings.Index(adv, wgPlaintextUnzonedHeading)
	if plainIdx < 0 {
		t.Fatalf("wg0.1 carries no zone of its own and must be reported as unzoned; "+
			"got: %s", adv)
	}
	if !strings.Contains(adv[plainIdx:], "wg0.1") {
		t.Errorf("a zone on wg0.0 was fanned SIDEWAYS onto the sibling unit's own "+
			"tunnel (a different device): %s", adv)
	}
}

// TestWGPlaintextWarningCoversDuplicateInterfacesBlocks: parseStatements
// APPENDS a repeated top-level block rather than merging it, and the compiler
// compiles every one (#5691) — so a WireGuard tunnel living in a second
// `interfaces {}` stanza must not be missed.
//
// Driven against the AST directly rather than through CompileConfig, because
// this shape needs the hierarchical parser (a `set` line cannot author two
// sibling top-level `interfaces` roots) and the fixture is deliberately minimal
// — no listen-port/private-key/peer, which the strict WireGuard gate would
// reject for reasons unrelated to #5618.
func TestWGPlaintextWarningCoversDuplicateInterfacesBlocks(t *testing.T) {
	tree, err := NewParser(`
interfaces {
    wg0 {
        unit 0 {
            tunnel {
                mode wireguard;
            }
        }
    }
}
interfaces {
    wg1 {
        tunnel {
            mode wireguard;
        }
    }
}
`).Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := warnWireGuardPlaintextUnadjudicatedAST(tree.Children)
	if len(got) != 1 {
		t.Fatalf("want ONE aggregated advisory, got %d: %v", len(got), got)
	}
	for _, want := range []string{"wg0.0", "wg1"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("missing %q in: %s", want, got[0])
		}
	}
}

// TestWGPlaintextWarningIsNotNameShaped keys the advisory on the tunnel MODE,
// not on the `wg` prefix.
//
// Nothing reserves `wg` — schema_interfaces.go accepts a wildcard interface
// name — so a lexical predicate would both MISS a WireGuard tunnel on an
// unconventionally-named interface and FIRE on an ordinary NIC that happens to
// be called `wg5`. Both directions are pinned here.
func TestWGPlaintextWarningIsNotNameShaped(t *testing.T) {
	t.Run("wg_named_nic_with_no_tunnel_is_quiet", func(t *testing.T) {
		cfg := compileWarn5618(t,
			"set interfaces wg5 unit 0 family inet address 192.0.2.1/24",
			"set security zones security-zone trust interfaces wg5.0",
		)
		if got := plaintextWarnings5618(cfg); len(got) != 0 {
			t.Errorf("a plain NIC named wg5 with no tunnel stanza must not be reported "+
				"as a WireGuard tunnel: %v", got)
		}
	})
	t.Run("non_wg_named_tunnel_still_fires", func(t *testing.T) {
		lines := wgTunnel5618("vpn-a", 0, 51820, wgKeyA, wgKeyB)
		lines = append(lines, "set security zones security-zone vpn interfaces vpn-a.0")
		cfg := compileWarn5618(t, lines...)
		got := plaintextWarnings5618(cfg)
		if len(got) != 1 {
			t.Fatalf("want exactly 1 advisory for a WireGuard tunnel on a non-`wg` "+
				"interface name, got %d: %v", len(got), cfg.Warnings)
		}
		if !strings.Contains(got[0], "vpn-a.0") {
			t.Errorf("advisory must name the tunnel whatever the interface is called: %s",
				got[0])
		}
	})
}

// TestWGPlaintextWarningFiresOnEveryCompilePath pins the coverage this
// advisory's own argument leans on.
//
// The operator who most needs telling is the one who does NOT re-commit after
// an upgrade: their config arrives by RESTART (Store.Load) or PEER-SYNC
// (Store.SyncApply), and both use the LENIENT entry point, not the strict one
// an operator drives by hand. An advisory that fired only on strict commit
// would systematically miss exactly the population it was written for, and
// every other test here would still be green.
//
// The node-aware variants are included because `apply-groups "${node}"` makes
// the two nodes compile different trees — an advisory that survived on node 0
// and vanished on node 1 would be worse than none.
func TestWGPlaintextWarningFiresOnEveryCompilePath(t *testing.T) {
	build := func(t *testing.T) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		lines := wgTunnel5618("wg0", 0, 51820, wgKeyA, wgKeyB)
		lines = append(lines, "set security zones security-zone vpn interfaces wg0.0")
		for _, line := range lines {
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		return tree
	}

	for _, tc := range []struct {
		name    string
		compile func(*ConfigTree) (*Config, error)
	}{
		{"strict_operator_commit", CompileConfig},
		{"lenient_restart_and_peer_sync", CompileConfigLenient},
		{"node0", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNode(tr, 0) }},
		{"node1", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNode(tr, 1) }},
		{"node0_lenient", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tr, 0) }},
		{"node1_lenient", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tr, 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.compile(build(t))
			if err != nil {
				t.Fatalf("compile: %v (a #5618 plaintext advisory must NEVER reject)", err)
			}
			got := plaintextWarnings5618(cfg)
			if len(got) != 1 {
				t.Fatalf("want exactly 1 #5618 advisory on the %s path, got %d: %v",
					tc.name, len(got), got)
			}
		})
	}
}
