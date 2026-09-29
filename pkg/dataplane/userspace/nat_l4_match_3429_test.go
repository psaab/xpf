// #3429: source-NAT `match destination-port` / `match application` enforcement.
// These tests prove the Go snapshot builder carries the L4 match constraints
// onto the userspace SourceNATRuleSnapshot (the per-flow match itself is
// enforced Rust-side in nat::tests::*_3429). Before the fix these match fields
// were parsed and compiled but DROPPED at the snapshot boundary, so a
// port/app-scoped source-NAT rule silently widened to every port/protocol.
// Dropping the builder assignment turns these RED.
package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// snatLenientSnapshots reproduces the issue #3546 path end to end: build a
// source-NAT rule from FLAT-SET commands (ParseSetCommand + SetPath per
// CLAUDE.md), lower it through the #1960 TOLERANT load (CompileConfigLenient —
// the peer-sync / corrupt-active path that downgrades the strict commit reject
// to a warning), then run the userspace source-NAT snapshot builder. A normal
// `commit` (CompileConfig) hard-rejects the bad dest-port, so the bug is only
// reachable here.
func snatLenientSnapshots(t *testing.T, dportCmd string) []SourceNATRuleSnapshot {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security nat source rule-set RS from zone lan",
		"set security nat source rule-set RS to zone wan",
		dportCmd,
		"set security nat source rule-set RS rule R1 then source-nat interface",
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return buildSourceNATSnapshots(cfg, nil)
}

// #3546 end-to-end: an all-nonnumeric source-NAT `match destination-port` that
// slips through the tolerant load path must fail CLOSED at the builder (the
// never-match sentinel), not widen to match-any-port. RED-on-revert: ignore
// InvalidDestinationPorts in sourceNATDestPortRanges and the empty
// DestinationPorts list yields empty MatchDestinationPorts = unconstrained.
func TestBuildSourceNATSnapshotsLenientNonnumericPortFailsClosed(t *testing.T) {
	snaps := snatLenientSnapshots(t,
		"set security nat source rule-set RS rule R1 match destination-port http")
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	got := snaps[0].MatchDestinationPorts
	if len(got) != 1 || got[0] != natNeverMatchPortRange {
		t.Fatalf("MatchDestinationPorts = %+v, want one never-match range %+v (fail closed via lenient path)",
			got, natNeverMatchPortRange)
	}
}

// #3546 over-reject control on the same lenient end-to-end path: a valid numeric
// dest-port must still compile to its exact wire range (no widening, no
// over-reject).
func TestBuildSourceNATSnapshotsLenientValidPortStillCompiles(t *testing.T) {
	snaps := snatLenientSnapshots(t,
		"set security nat source rule-set RS rule R1 match destination-port 8080")
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	got := snaps[0].MatchDestinationPorts
	want := []NatPortRangeWire{{Low: 8080, High: 8080}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("MatchDestinationPorts = %+v, want %+v", got, want)
	}
}

func TestBuildSourceNATSnapshotsCarriesDestinationPortMatch(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name: "r1",
				Match: config.NATMatch{
					// `destination-port 20000 to 20003` -> compiler stores the
					// range expanded to individual ports; the builder coalesces
					// them back to one wire range.
					DestinationPorts: []int{20000, 20001, 20002, 20003},
				},
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	got := snaps[0].MatchDestinationPorts
	want := []NatPortRangeWire{{Low: 20000, High: 20003}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("MatchDestinationPorts = %+v, want %+v", got, want)
	}
}

func TestBuildSourceNATSnapshotsDropsOutOfRangePort(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name: "r1",
				Match: config.NATMatch{
					// 0 and >65535 must be dropped (fail closed), 443 kept.
					DestinationPorts: []int{0, 443, 70000},
				},
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	got := snaps[0].MatchDestinationPorts
	want := []NatPortRangeWire{{Low: 443, High: 443}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("MatchDestinationPorts = %+v, want %+v (out-of-range dropped)", got, want)
	}
}

// #3471 AGY fail-open: a destination-port constraint whose ports are ALL out of
// range must NOT coalesce to an empty list — empty means "unconstrained" =
// match-any-port. It must emit the never-match sentinel so the rule matches
// nothing. RED-on-revert: with the plain coalescePortRanges (drop-to-empty),
// MatchDestinationPorts is empty and the rule widens to every port.
func TestBuildSourceNATSnapshotsAllOutOfRangePortFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name: "r1",
				Match: config.NATMatch{
					DestinationPorts: []int{0, 70000, 99999},
				},
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	got := snaps[0].MatchDestinationPorts
	if len(got) != 1 || got[0] != natNeverMatchPortRange {
		t.Fatalf("MatchDestinationPorts = %+v, want one never-match range %+v (fail closed, not empty wildcard)",
			got, natNeverMatchPortRange)
	}
}

// #3546 fail-open residual: an all-nonnumeric source-NAT `match
// destination-port` (e.g. `http`) parses to an EMPTY DestinationPorts list with
// the raw token preserved on InvalidDestinationPorts. The builder must read
// InvalidDestinationPorts and fail CLOSED (the never-match sentinel) so the rule
// matches NOTHING on the #1960 lenient / peer-sync load path, rather than
// coalescing to empty = unconstrained match-any-port. RED-on-revert: a builder
// that consults only DestinationPorts sees an empty list, never trips the
// fail-closed branch, and emits empty MatchDestinationPorts (widen to any port).
func TestBuildSourceNATSnapshotsAllNonnumericPortFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name: "r1",
				Match: config.NATMatch{
					// `match destination-port http`: not numeric, not a service
					// name (the NAT match grammar has no name resolution), so the
					// parser surfaces it as an invalid token with no valid ports.
					DestinationPorts:        nil,
					InvalidDestinationPorts: []string{"http"},
				},
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	got := snaps[0].MatchDestinationPorts
	if len(got) != 1 || got[0] != natNeverMatchPortRange {
		t.Fatalf("MatchDestinationPorts = %+v, want one never-match range %+v (fail closed, not empty wildcard)",
			got, natNeverMatchPortRange)
	}
}

// #3546 over-reject control: a mix of one valid numeric port and an invalid
// token (`[ http 8080 ]`) must keep the valid port (8080) on the lenient path,
// mirroring the DNAT builder — the invalid token alone must not poison a rule
// that still carries a usable constraint. Also guards against over-rejecting a
// plain valid numeric source-NAT dest-port.
func TestBuildSourceNATSnapshotsValidPortWithInvalidTokenKeepsValid(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name: "r1",
				Match: config.NATMatch{
					DestinationPorts:        []int{8080},
					InvalidDestinationPorts: []string{"http"},
				},
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	got := snaps[0].MatchDestinationPorts
	want := []NatPortRangeWire{{Low: 8080, High: 8080}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("MatchDestinationPorts = %+v, want %+v (valid port kept, invalid token dropped)", got, want)
	}
}

// #3471 Codex fail-open: an application whose protocol is empty or unresolvable
// must emit the never-match protocol sentinel, NOT natProtoAny (256, wildcard).
// RED-on-revert: returning natProtoAny widens the app term to every protocol.
func TestBuildSourceNATSnapshotsAppEmptyProtocolFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"app-noproto": {Name: "app-noproto", Protocol: "", DestinationPort: "443"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "app-noproto"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	apps := buildSourceNATSnapshots(cfg, nil)[0].MatchApplications
	if len(apps) != 1 || apps[0].Protocol != natProtoNever {
		t.Fatalf("MatchApplications = %+v, want one never-match term (proto %d), NOT natProtoAny %d",
			apps, natProtoNever, natProtoAny)
	}
}

func TestBuildSourceNATSnapshotsAppUnknownProtocolFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"app-bad": {Name: "app-bad", Protocol: "frobnicate", DestinationPort: "443"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "app-bad"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	apps := buildSourceNATSnapshots(cfg, nil)[0].MatchApplications
	if len(apps) != 1 || apps[0].Protocol != natProtoNever {
		t.Fatalf("MatchApplications = %+v, want one never-match term (proto %d)", apps, natProtoNever)
	}
}

func TestBuildSourceNATSnapshotsCarriesApplicationMatch(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"app-https": {Name: "app-https", Protocol: "tcp", DestinationPort: "443"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "app-https"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	apps := snaps[0].MatchApplications
	if len(apps) != 1 {
		t.Fatalf("MatchApplications = %+v, want 1 term", apps)
	}
	if apps[0].Protocol != 6 { // tcp
		t.Fatalf("term protocol = %d, want 6 (tcp)", apps[0].Protocol)
	}
	if len(apps[0].Ports) != 1 || apps[0].Ports[0] != (NatPortRangeWire{Low: 443, High: 443}) {
		t.Fatalf("term ports = %+v, want [{443 443}]", apps[0].Ports)
	}
}

func TestBuildSourceNATSnapshotsCarriesApplicationICMPTypeAndCode11064(t *testing.T) {
	icmpType, icmpCode := uint8(8), uint8(3)
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"icmp-numeric": {
			Name:     "icmp-numeric",
			Protocol: "1",
			ICMPType: &icmpType,
			ICMPCode: &icmpCode,
		},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "rs",
		FromZone: "lan",
		ToZone:   "wan",
		Rules: []*config.NATRule{{
			Name:  "ping-only",
			Match: config.NATMatch{Application: "icmp-numeric"},
			Then:  config.NATThen{Type: config.NATSource, Interface: true},
		}},
	}}

	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 || len(snaps[0].MatchApplications) != 1 {
		t.Fatalf("source NAT applications = %+v, want one numeric ICMP term", snaps)
	}
	term := snaps[0].MatchApplications[0]
	if term.Protocol != 1 || term.ICMPType == nil || *term.ICMPType != 8 ||
		term.ICMPCode == nil || *term.ICMPCode != 3 {
		t.Fatalf("SNAT application term = %+v, want proto=1 icmp-type=8 icmp-code=3", term)
	}
	wireJSON, err := json.Marshal(term)
	if err != nil {
		t.Fatalf("marshal SNAT application term: %v", err)
	}
	var wire map[string]uint8
	if err := json.Unmarshal(wireJSON, &wire); err != nil {
		t.Fatalf("decode SNAT application wire fields: %v", err)
	}
	if wire["icmp_type"] != 8 || wire["icmp_code"] != 3 {
		t.Fatalf("SNAT application JSON = %s, want icmp_type=8 icmp_code=3", wireJSON)
	}
}

func TestBuildSourceNATSnapshotsUnresolvableApplicationFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "does-not-exist"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	apps := snaps[0].MatchApplications
	if len(apps) != 1 || apps[0].Protocol != natProtoNever {
		t.Fatalf("MatchApplications = %+v, want one never-match term (proto %d)", apps, natProtoNever)
	}
}

// #3491: the application's source-port constraint must be carried onto the
// snapshot term's SrcPorts. Before the fix buildSourceNATAppTerms read only
// DestinationPort, so a source-NAT rule whose `match application` constrained
// the source port widened to every source port (fail open). Dropping the
// SrcPorts assignment turns this RED.
func TestBuildSourceNATSnapshotsCarriesApplicationSourcePortMatch(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"app-svc": {Name: "app-svc", Protocol: "tcp", SourcePort: "12345", DestinationPort: "443"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "app-svc"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	apps := snaps[0].MatchApplications
	if len(apps) != 1 {
		t.Fatalf("MatchApplications = %+v, want 1 term", apps)
	}
	if len(apps[0].Ports) != 1 || apps[0].Ports[0] != (NatPortRangeWire{Low: 443, High: 443}) {
		t.Fatalf("term ports = %+v, want [{443 443}]", apps[0].Ports)
	}
	if len(apps[0].SrcPorts) != 1 || apps[0].SrcPorts[0] != (NatPortRangeWire{Low: 12345, High: 12345}) {
		t.Fatalf("term src ports = %+v, want [{12345 12345}]", apps[0].SrcPorts)
	}
}

// #3491: an application whose source-port spec is non-empty but coalesces to
// nothing (all out of 1..65535) must fail CLOSED with the never-match sentinel,
// NOT widen to any source port (empty SrcPorts).
func TestBuildSourceNATSnapshotsAppAllOutOfRangeSourcePortFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"app-bad-sport": {Name: "app-bad-sport", Protocol: "tcp", SourcePort: "70000"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "app-bad-sport"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	apps := snaps[0].MatchApplications
	if len(apps) != 1 {
		t.Fatalf("MatchApplications = %+v, want 1 term", apps)
	}
	want := []NatPortRangeWire{natNeverMatchPortRange}
	if len(apps[0].SrcPorts) != len(want) || apps[0].SrcPorts[0] != want[0] {
		t.Fatalf("term src ports = %+v, want one never-match range %+v (fail closed, not empty wildcard)",
			apps[0].SrcPorts, want)
	}
}

func TestBuildSourceNATSnapshotsUnconstrainedHasNoL4Match(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name: "r1",
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps[0].MatchDestinationPorts) != 0 || len(snaps[0].MatchApplications) != 0 {
		t.Fatalf("unconstrained rule must carry no L4 match: %+v", snaps[0])
	}
}
