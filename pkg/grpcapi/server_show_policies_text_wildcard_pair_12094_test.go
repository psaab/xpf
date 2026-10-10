package grpcapi

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #12094: the gRPC text hit-count and detail surfaces skipped any zone-pair
// stanza whose zones were not EXACT-string-equal to the `from-zone X to-zone Y`
// filter, so a `from-zone any` / `to-zone any` stanza that the runtime
// ENFORCES for X->Y (policymatch Tiers 2-3) vanished from the filtered output.
// The filtered surfaces must include applicable wildcard stanzas in the
// runtime's tier order — exact, then single-wildcard, then both-any — followed
// by the governing globals, while still excluding an unrelated concrete pair.

// wildcardPairFilterStore builds a probe config: an exact trust->untrust
// stanza, single-wildcard any->untrust + trust->any stanzas, a both-any
// stanza, an unrelated dmz->untrust stanza (must stay excluded), one governing
// global, plus the zones they reference. Stanzas are deliberately placed in
// reverse-tier config order so a passing test proves the re-ordering, not raw
// placement.
func wildcardPairFilterStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
        security-zone dmz;
    }
    policies {
        from-zone any to-zone any {
            policy both-any-deny {
                match { source-address any; destination-address any; application any; }
                then { deny; }
            }
        }
        from-zone trust to-zone any {
            policy wild-to-any {
                match { source-address any; destination-address any; application any; }
                then { deny; }
            }
        }
        from-zone any to-zone untrust {
            policy wild-deny {
                match { source-address any; destination-address any; application any; }
                then { deny; }
            }
        }
        from-zone trust to-zone untrust {
            policy exact-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        from-zone dmz to-zone untrust {
            policy off-pair {
                match { source-address any; destination-address any; application any; }
                then { deny; }
            }
        }
        global {
            policy open-global {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if cfg := store.ActiveConfig(); cfg == nil || len(cfg.Security.Policies) != 5 {
		t.Fatalf("expected 5 zone-pair stanzas, got %v", cfg)
	}
	return store
}

type wildcardPairCounterDP12094 struct {
	*dataplane.Manager
	counters map[uint32]dataplane.CounterValue
}

func (*wildcardPairCounterDP12094) IsLoaded() bool { return true }

func (d *wildcardPairCounterDP12094) ReadPolicyCounters(id uint32) (dataplane.CounterValue, error) {
	return d.counters[id], nil
}

func (d *wildcardPairCounterDP12094) ReadAllPolicyCounters(*config.Config) (map[uint32]dataplane.CounterValue, error) {
	return d.counters, nil
}

func wildcardPairCounterServer12094(t *testing.T) (*Server, *config.Config) {
	t.Helper()
	store := wildcardPairFilterStore(t)
	cfg := store.ActiveConfig()
	cfg.Security.PolicyStatsEnabled = true
	return &Server{
		store: store,
		dp: &wildcardPairCounterDP12094{
			Manager:  dataplane.New(),
			counters: wildcardPairCounters12094(cfg),
		},
	}, cfg
}

func wildcardPairCounters12094(cfg *config.Config) map[uint32]dataplane.CounterValue {
	counters := make(map[uint32]dataplane.CounterValue)
	for setIdx, zpp := range cfg.Security.Policies {
		for ruleIdx := range zpp.Policies {
			id := uint32(setIdx)*dataplane.MaxRulesPerPolicy + uint32(ruleIdx)
			packets := uint64(id) + 1000
			counters[id] = dataplane.CounterValue{Packets: packets, Bytes: packets * 10}
		}
	}
	globalSetID := uint32(len(cfg.Security.Policies))
	for ruleIdx := range cfg.Security.GlobalPolicies {
		id := globalSetID*dataplane.MaxRulesPerPolicy + uint32(ruleIdx)
		packets := uint64(id) + 1000
		counters[id] = dataplane.CounterValue{Packets: packets, Bytes: packets * 10}
	}
	counters[dataplane.DefaultPolicySentinelID] = dataplane.CounterValue{Packets: 9000, Bytes: 90000}
	return counters
}

func wildcardHitCountRow12094(out, name string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, name) {
			return line
		}
	}
	return ""
}

func wildcardDetailRuleLine12094(out, name string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Policy: "+name+",") {
			return line
		}
	}
	return ""
}

// TestGRPCHitCountFilteredKeepsWildcardPairs covers the gRPC text hit-count
// surface. FAIL-ON-REVERT: restoring the exact-string skip drops wild-deny /
// wild-to-any / both-any-deny from the filtered output, so the assertions go
// RED.
func TestGRPCHitCountFilteredKeepsWildcardPairs(t *testing.T) {
	s, _ := wildcardPairCounterServer12094(t)

	var buf strings.Builder
	s.showPoliciesHitCount("from-zone trust to-zone untrust", &buf)
	var allBuf strings.Builder
	s.showPoliciesHitCount("", &allBuf)
	all := allBuf.String()

	out := buf.String()

	for _, name := range []string{"exact-allow", "wild-to-any", "wild-deny", "both-any-deny", "open-global"} {
		if !strings.Contains(out, name) {
			t.Fatalf("filtered hit-count dropped %q (wildcard stanza enforced for trust->untrust — #12094 regression):\n%s", name, out)
		}
	}
	if strings.Contains(out, "off-pair") {
		t.Fatalf("filtered hit-count leaked an unrelated pair (dmz->untrust):\n%s", out)
	}
	assertPolicyOrder(t, out, []string{"exact-allow", "wild-to-any", "wild-deny", "both-any-deny", "open-global"})
	for _, name := range []string{"wild-to-any", "wild-deny", "both-any-deny"} {
		if got, want := wildcardHitCountRow12094(out, name), wildcardHitCountRow12094(all, name); got != want {
			t.Errorf("%s filtered counter row = %q, unfiltered row = %q", name, got, want)
		}
	}
}

// TestGRPCDetailFilteredKeepsWildcardPairs covers the gRPC text detail
// surface. FAIL-ON-REVERT: restoring the exact-string skip drops the wildcard
// policy blocks, so the assertions go RED.
func TestGRPCDetailFilteredKeepsWildcardPairs(t *testing.T) {
	s, _ := wildcardPairCounterServer12094(t)

	var buf strings.Builder
	s.showPoliciesDetail("from-zone trust to-zone untrust", &buf)
	out := buf.String()
	var allBuf strings.Builder
	s.showPoliciesDetail("", &allBuf)
	all := allBuf.String()

	for _, name := range []string{"Policy: exact-allow", "Policy: wild-to-any", "Policy: wild-deny", "Policy: both-any-deny", "Policy: open-global"} {
		if !strings.Contains(out, name) {
			t.Fatalf("filtered detail dropped %q (wildcard stanza enforced for trust->untrust — #12094 regression):\n%s", name, out)
		}
	}
	if strings.Contains(out, "Policy: off-pair") {
		t.Fatalf("filtered detail leaked an unrelated pair (dmz->untrust):\n%s", out)
	}
	assertPolicyOrder(t, out, []string{"Policy: exact-allow", "Policy: wild-to-any", "Policy: wild-deny", "Policy: both-any-deny", "Policy: open-global"})
	for _, name := range []string{"wild-to-any", "wild-deny", "both-any-deny"} {
		if got, want := wildcardDetailRuleLine12094(out, name), wildcardDetailRuleLine12094(all, name); got != want {
			t.Errorf("%s filtered Index line = %q, unfiltered line = %q", name, got, want)
		}
	}
}

func TestGRPCHostFilterExcludesTransitWildcards12094(t *testing.T) {
	store := wildcardPairFilterStore(t)
	cfg := store.ActiveConfig()
	cfg.Security.PolicyStatsEnabled = true
	cfg.Security.Policies = append(cfg.Security.Policies,
		&config.ZonePairPolicies{
			FromZone: "trust", ToZone: "junos-host",
			Policies: []*config.Policy{{Name: "host-exact", Action: config.PolicyDeny}},
		},
		&config.ZonePairPolicies{
			FromZone: "any", ToZone: "junos-host",
			Policies: []*config.Policy{{Name: "host-from-any", Action: config.PolicyDeny}},
		},
	)
	cfg.Security.GlobalPolicies = append(cfg.Security.GlobalPolicies, &config.Policy{
		Name: "g-host", Action: config.PolicyDeny,
		Match: config.PolicyMatch{ToZones: []string{"junos-host"}},
	})
	counters := wildcardPairCounters12094(cfg)
	s := &Server{
		store: store,
		dp: &wildcardPairCounterDP12094{
			Manager:  dataplane.New(),
			counters: counters,
		},
	}
	var buf strings.Builder
	s.showPoliciesHitCount("from-zone trust to-zone junos-host", &buf)
	out := buf.String()

	assertPolicyOrder(t, out, []string{"host-exact", "host-from-any", "open-global", "g-host"})
	for _, excluded := range []string{"wild-to-any", "wild-deny", "both-any-deny"} {
		if strings.Contains(out, excluded) {
			t.Fatalf("host-bound filtered view listed transit-only policy %q:\n%s", excluded, out)
		}
	}
	var totalLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Total") {
			totalLine = line
			break
		}
	}
	hostSetID := uint32(5)
	globalSetID := uint32(len(cfg.Security.Policies))
	wantPackets := counters[hostSetID*dataplane.MaxRulesPerPolicy].Packets +
		counters[(hostSetID+1)*dataplane.MaxRulesPerPolicy].Packets +
		counters[globalSetID*dataplane.MaxRulesPerPolicy].Packets +
		counters[globalSetID*dataplane.MaxRulesPerPolicy+1].Packets
	wantBytes := counters[hostSetID*dataplane.MaxRulesPerPolicy].Bytes +
		counters[(hostSetID+1)*dataplane.MaxRulesPerPolicy].Bytes +
		counters[globalSetID*dataplane.MaxRulesPerPolicy].Bytes +
		counters[globalSetID*dataplane.MaxRulesPerPolicy+1].Bytes
	fields := strings.Fields(totalLine)
	if len(fields) < 2 || fields[len(fields)-2] != strconv.FormatUint(wantPackets, 10) ||
		fields[len(fields)-1] != strconv.FormatUint(wantBytes, 10) {
		t.Fatalf("host-bound total = %q, want only exact/from-any/host-globals totals %d/%d:\n%s",
			totalLine, wantPackets, wantBytes, out)
	}
}

// assertPolicyOrder requires needle[i] to appear strictly before needle[i+1]
// in out, proving the exact -> single-wildcard -> both-any -> global tier
// order rather than raw config placement.
func assertPolicyOrder(t *testing.T, out string, needles []string) {
	t.Helper()
	prev := -1
	for _, n := range needles {
		idx := strings.Index(out, n)
		if idx < 0 {
			t.Fatalf("policy %q not found in filtered output:\n%s", n, out)
		}
		if idx <= prev {
			t.Fatalf("policy %q out of tier order (exact -> single-wildcard -> both-any -> global):\n%s", n, out)
		}
		prev = idx
	}
}
