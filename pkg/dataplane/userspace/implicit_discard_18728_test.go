package userspace

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #18728: the Junos implicit final discard. A filter with no terminal
// catch-all term (config.FirewallFilterHasCatchAll false) gets a synthetic
// LAST term `implicit-discard` (unconstrained, counted, discard) in its
// dataplane snapshot, so the helper drops and counts what matched no authored
// term. A filter with a catch-all gets nothing.
//
// The same snapshots are written to testdata/firewall_implicit_discard_18728.json
// and decoded by the Rust cells in
// userspace-dp/src/filter/implicit_discard_18728_tests.rs, so the Rust
// verdicts are measured on the exact Go builder wire, not a transcription.

const implicitDiscardFixture18728 = "../../../testdata/firewall_implicit_discard_18728.json"

func implicitDiscardCfg18728() *config.Config {
	ssh := func(addrFamily string) *config.FirewallFilterTerm {
		return &config.FirewallFilterTerm{
			Name: "ssh", Protocols: []string{"tcp"}, DestinationPorts: []string{"22"},
			Count: "ssh-" + addrFamily, Action: config.FilterActionAccept,
		}
	}
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		// Allowlist, no catch-all: synthetic term.
		"allow-ssh-v4": {Name: "allow-ssh-v4", Terms: []*config.FirewallFilterTerm{ssh("v4")}},
		// Explicit permit-by-default: no synthetic term.
		"permit-explicit": {Name: "permit-explicit", Terms: []*config.FirewallFilterTerm{
			ssh("v4"),
			{Name: "default", Action: config.FilterActionAccept},
		}},
		// Refined predicate: an unconstrained modifier-only term terminates
		// as implicit accept (#14632), so it IS a catch-all.
		"modifier-catch": {Name: "modifier-catch", Terms: []*config.FirewallFilterTerm{
			{Name: "count-all", Count: "all"},
		}},
		// Refined predicate: an unconstrained routing-instance term
		// terminates on the routing decision, so it IS a catch-all.
		"ri-catch": {Name: "ri-catch", Terms: []*config.FirewallFilterTerm{
			{Name: "steer-all", RoutingInstance: "blue"},
		}},
		// A constrained routing-instance term is not: traffic outside its
		// scope reaches the synthetic discard; traffic inside it takes the
		// #6835 defer on a non-routing walk.
		"ri-steer": {Name: "ri-steer", Terms: []*config.FirewallFilterTerm{
			{Name: "steer", SourceAddresses: []string{"10.0.0.0/8"}, RoutingInstance: "blue"},
		}},
		// An authored `then { count; next term; }` falls through, so it is
		// not a catch-all even unconstrained.
		"count-next": {Name: "count-next", Terms: []*config.FirewallFilterTerm{
			{Name: "mark", Count: "mark", NextTerm: true},
		}},
		// No terms at all: discard everything (the Junos empty filter).
		"empty": {Name: "empty"},
		// A pure-accept allowlist with no count/log/forwarding-class: before
		// #18728 its compiled Filter needed no TX evaluation at all, so an
		// OUTPUT binding never ran. The synthetic counted discard must make
		// needs_tx_eval true or the output implicit discard is dead.
		"allow-web-v4": {Name: "allow-web-v4", Terms: []*config.FirewallFilterTerm{
			{Name: "web", Protocols: []string{"tcp"}, DestinationPorts: []string{"443"}, Action: config.FilterActionAccept},
		}},
	}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"allow-ssh-v6": {Name: "allow-ssh-v6", Terms: []*config.FirewallFilterTerm{ssh("v6")}},
	}
	return cfg
}

func implicitDiscardWant18728() map[string]bool {
	return map[string]bool{
		"inet:allow-ssh-v4":    true,
		"inet:permit-explicit": false,
		"inet:modifier-catch":  false,
		"inet:ri-catch":        false,
		"inet:ri-steer":        true,
		"inet:count-next":      true,
		"inet:empty":           true,
		"inet:allow-web-v4":    true,
		"inet6:allow-ssh-v6":   true,
	}
}

func TestImplicitDiscardTermOnlyWithoutCatchAll18728(t *testing.T) {
	cfg := implicitDiscardCfg18728()
	want := implicitDiscardWant18728()
	snaps := buildFirewallFilterSnapshots(cfg)
	if len(snaps) != len(want) {
		t.Fatalf("got %d snapshots, want %d", len(snaps), len(want))
	}
	for _, snap := range snaps {
		key := snap.Family + ":" + snap.Name
		wantImplicit, ok := want[key]
		if !ok {
			t.Fatalf("unexpected snapshot %s", key)
		}
		var filter *config.FirewallFilter
		if snap.Family == "inet" {
			filter = cfg.Firewall.FiltersInet[snap.Name]
		} else {
			filter = cfg.Firewall.FiltersInet6[snap.Name]
		}
		authored := len(filter.Terms)
		if snap.ImplicitDiscard != wantImplicit {
			t.Errorf("%s: ImplicitDiscard = %v, want %v", key, snap.ImplicitDiscard, wantImplicit)
		}
		if !wantImplicit {
			if len(snap.Terms) != authored {
				t.Errorf("%s: %d snapshot terms, want the %d authored (a catch-all filter gets no synthetic term)", key, len(snap.Terms), authored)
			}
			for _, term := range snap.Terms {
				if term.Name == ImplicitDiscardTermName {
					t.Errorf("%s: catch-all filter carries the synthetic term", key)
				}
			}
			continue
		}
		if len(snap.Terms) != authored+1 {
			t.Fatalf("%s: %d snapshot terms, want %d authored + 1 synthetic", key, len(snap.Terms), authored)
		}
		last := snap.Terms[len(snap.Terms)-1]
		if last.Name != ImplicitDiscardTermName || last.Count != ImplicitDiscardTermName ||
			last.Action != string(config.FilterActionDiscard) || last.NextTerm || last.RoutingInstance != "" {
			t.Errorf("%s: last term = %+v, want the unconstrained counted discard %q", key, last, ImplicitDiscardTermName)
		}
		if len(last.SourceAddresses)+len(last.DestAddresses)+len(last.Protocols)+len(last.SourcePorts)+
			len(last.DestPorts)+len(last.DSCPValues)+len(last.ICMPTypes)+len(last.ICMPCodes) != 0 ||
			last.SourceConstrained || last.DestConstrained || last.TCPFlags != nil || last.IsFragment {
			t.Errorf("%s: synthetic term must have no `from` constraint: %+v", key, last)
		}
	}
}

// The synthetic term is decided by the SAME predicate as the commit warning,
// so `commit check` names exactly the filters that will discard unmatched
// traffic. A predicate drift (one side refined, the other not) reds here.
func TestImplicitDiscardSnapshotAgreesWithCommitWarning18728(t *testing.T) {
	cfg := implicitDiscardCfg18728()
	for _, snap := range buildFirewallFilterSnapshots(cfg) {
		var filter *config.FirewallFilter
		if snap.Family == "inet" {
			filter = cfg.Firewall.FiltersInet[snap.Name]
		} else {
			filter = cfg.Firewall.FiltersInet6[snap.Name]
		}
		if snap.ImplicitDiscard == config.FirewallFilterHasCatchAll(filter) {
			t.Errorf("%s:%s: ImplicitDiscard=%v but FirewallFilterHasCatchAll=%v", snap.Family, snap.Name,
				snap.ImplicitDiscard, config.FirewallFilterHasCatchAll(filter))
		}
	}
}

// The effective (`show firewall effective`) renderer labels the synthetic
// term so it is not read as authored, and leaves catch-all filters alone.
func TestImplicitDiscardEffectiveRenderLabelsSyntheticTerm18728(t *testing.T) {
	cfg := implicitDiscardCfg18728()
	for _, snap := range buildFirewallFilterSnapshots(cfg) {
		snap := snap
		out := RenderFirewallFilterSnapshot(&snap)
		labelled := strings.Contains(out, "Term: implicit-discard (Junos implicit final discard: no term above matched)")
		if labelled != snap.ImplicitDiscard {
			t.Errorf("%s:%s: labelled=%v ImplicitDiscard=%v\n%s", snap.Family, snap.Name, labelled, snap.ImplicitDiscard, out)
		}
	}
}

// TestImplicitDiscardSnapshotFixtureFresh18728 pins the snapshots the Rust
// cells decode. Regenerate with UPDATE_18728=1 and rerun both suites.
func TestImplicitDiscardSnapshotFixtureFresh18728(t *testing.T) {
	got, err := json.MarshalIndent(buildFirewallFilterSnapshots(implicitDiscardCfg18728()), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')
	if os.Getenv("UPDATE_18728") == "1" {
		if err := os.WriteFile(implicitDiscardFixture18728, got, 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return
	}
	want, err := os.ReadFile(implicitDiscardFixture18728)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Go builder filter snapshots drifted from %s; regenerate with UPDATE_18728=1 and rerun the Go and Rust cells",
			implicitDiscardFixture18728)
	}
}

// ImplicitDiscardCounterForFilter reads the synthetic term's row at the
// ordinal after every authored term, and only when the row carries the
// synthetic name (an older helper never publishes one).
func TestImplicitDiscardCounterLookup18728(t *testing.T) {
	cfg := implicitDiscardCfg18728()
	f := cfg.Firewall.FiltersInet["allow-ssh-v4"]
	status := &ProcessStatus{FilterTermCounters: []FirewallFilterTermCounterStatus{
		{Family: "inet", FilterName: "allow-ssh-v4", TermName: "ssh", TermOrdinal: 0, Packets: 5, Bytes: 500},
		{Family: "inet", FilterName: "allow-ssh-v4", TermName: ImplicitDiscardTermName, TermOrdinal: 1, Packets: 7, Bytes: 700},
		{Family: "inet", FilterName: "permit-explicit", TermName: ImplicitDiscardTermName, TermOrdinal: 2, Packets: 9, Bytes: 900},
	}}
	index := BuildFirewallFilterTermCounterIndexForConfig(status, cfg)
	row, ok := ImplicitDiscardCounterForFilter(index, "inet", "allow-ssh-v4", f)
	if !ok || row.Packets != 7 || row.Bytes != 700 {
		t.Fatalf("allow-ssh-v4 implicit counter = %+v ok=%v, want 7/700", row, ok)
	}
	// A catch-all filter has no synthetic term, whatever the index says.
	if _, ok := ImplicitDiscardCounterForFilter(index, "inet", "permit-explicit", cfg.Firewall.FiltersInet["permit-explicit"]); ok {
		t.Fatal("catch-all filter must report no implicit-discard reading")
	}
	// A row at the right ordinal but with an authored name (an older helper,
	// or a filter changed under a stale status) is not the synthetic term.
	stale := &ProcessStatus{FilterTermCounters: []FirewallFilterTermCounterStatus{
		{Family: "inet", FilterName: "allow-ssh-v4", TermName: "ssh2", TermOrdinal: 1, Packets: 3, Bytes: 300},
	}}
	if _, ok := ImplicitDiscardCounterForFilter(BuildFirewallFilterTermCounterIndexForConfig(stale, cfg), "inet", "allow-ssh-v4", f); ok {
		t.Fatal("a non-synthetic row at the synthetic ordinal must not be reported as the implicit-discard counter")
	}
}

// authoredFilterSnapshots18728 returns snaps with each marked filter's
// synthetic implicit-discard term removed, for cells written before #18728
// that pin the lowering of the terms they AUTHORED. It does not hide a
// malformed append: a marked filter must end in exactly
// implicitDiscardTermSnapshot(), and an unmarked one must not carry it.
func authoredFilterSnapshots18728(t *testing.T, snaps []FirewallFilterSnapshot) []FirewallFilterSnapshot {
	t.Helper()
	want := implicitDiscardTermSnapshot()
	out := make([]FirewallFilterSnapshot, len(snaps))
	for i, snap := range snaps {
		n := len(snap.Terms)
		if snap.ImplicitDiscard {
			if n == 0 || !reflect.DeepEqual(snap.Terms[n-1], want) {
				t.Fatalf("%s:%s is marked ImplicitDiscard but does not end in the synthetic term: %+v", snap.Family, snap.Name, snap.Terms)
			}
			snap.Terms = snap.Terms[: n-1 : n-1]
		} else if n > 0 && snap.Terms[n-1].Name == ImplicitDiscardTermName && reflect.DeepEqual(snap.Terms[n-1], want) {
			t.Fatalf("%s:%s carries the synthetic term without the marker", snap.Family, snap.Name)
		}
		out[i] = snap
	}
	return out
}
