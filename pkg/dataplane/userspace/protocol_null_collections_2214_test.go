package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2214 (HIGH, #1961-class): a nil Go slice on a snapshot field declared
// WITHOUT `,omitempty` marshals as JSON `null`. The Rust helper decodes
// NAT64RuleSnapshot.pool_addresses and FirewallFilterSnapshot.terms as
// `Vec<T>`, which rejects an explicit `null` ("invalid type: null, expected a
// sequence") and aborts the ENTIRE apply_snapshot decode -> helper EOF ->
// enabled:false -> NO TRANSIT for the whole config.
//
// Two reachable triggers verified in the issue:
//   A: a NAT64 rule with a prefix but no resolvable source-pool -> the Go
//      builder leaves pool_addresses nil.
//   B: a firewall filter declared with zero terms -> the Go builder returns
//      nil terms.
//
// The fix initializes both slices non-nil at the build site so they marshal as
// `[]`. These tests FAIL on the pre-fix code (the marshaled wire carries `null`
// for those keys) and pass after — they are the no-transit-prevention proof on
// the Go side. The Rust side independently tolerates `null` (see
// userspace-dp/src/protocol/{nat,security}.rs + the config_snapshot_*_null
// tests) for cross-version safety.

// nat64NoPoolCfg builds a config with a single NAT64 rule whose source-pool is
// absent, so buildNAT64Snapshots resolves zero pool addresses.
func nat64NoPoolCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{
		{Name: "rs1", Prefix: "64:ff9b::/96"}, // no SourcePool
	}
	return cfg
}

// emptyFilterCfg builds a config with a single inet filter declared with zero
// terms (the compiler stores the filter regardless of term count).
func emptyFilterCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"EMPTY": {Name: "EMPTY"}, // Terms == nil
	}
	return cfg
}

// fieldRawMessage marshals v, decodes it as a generic object, and returns the
// raw JSON bytes for the named top-level key (or the empty string if absent).
func fieldRawMessage(t *testing.T, v any, key string) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatalf("unmarshal to object: %v", err)
	}
	raw, ok := obj[key]
	if !ok {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func TestNAT64EmptyPoolMarshalsEmptyArrayNotNull(t *testing.T) {
	rules := buildNAT64Snapshots(nat64NoPoolCfg())
	if len(rules) != 1 {
		t.Fatalf("buildNAT64Snapshots = %d rules, want 1 (rule must NOT be dropped)", len(rules))
	}
	if rules[0].PoolAddresses == nil {
		t.Fatal("PoolAddresses is nil; the Go builder must initialize it non-nil so it marshals as [] not null (#2214)")
	}
	raw := fieldRawMessage(t, rules[0], "pool_addresses")
	if raw == "null" || raw == "" {
		t.Fatalf("pool_addresses marshaled as %q, want \"[]\" — a null aborts the Rust snapshot decode (#2214 no-transit)", raw)
	}
	if raw != "[]" {
		t.Fatalf("pool_addresses = %q, want \"[]\"", raw)
	}
}

func TestEmptyFilterTermsMarshalsEmptyArrayNotNull(t *testing.T) {
	filters := buildFirewallFilterSnapshots(emptyFilterCfg())
	if len(filters) != 1 {
		t.Fatalf("buildFirewallFilterSnapshots = %d filters, want 1", len(filters))
	}
	if filters[0].Terms == nil {
		t.Fatal("Terms is nil; the Go builder must return a non-nil empty slice so it marshals as [] not null (#2214)")
	}
	raw := fieldRawMessage(t, filters[0], "terms")
	if raw == "null" || raw == "" {
		t.Fatalf("terms marshaled as %q, want an array — a null aborts the Rust snapshot decode (#2214 no-transit)", raw)
	}
	// #18728: a zero-term filter is the Junos discard-everything filter, so
	// its snapshot carries exactly the synthetic implicit-discard term. The
	// builder's own zero-term result is still the non-nil [] pinned by
	// TestBuildFilterTermSnapshotsNeverNil.
	if raw != implicitDiscardTermWire2214 {
		t.Fatalf("terms = %q, want %q", raw, implicitDiscardTermWire2214)
	}
}

// implicitDiscardTermWire2214 is the wire of a zero-term filter's terms since
// #18728: the lone synthetic implicit-discard term.
const implicitDiscardTermWire2214 = `[{"name":"implicit-discard","action":"discard","count":"implicit-discard"}]`

// buildFilterTermSnapshots returns a non-nil empty slice for a filter with no
// terms (covers nil filter and the all-nil-terms case too).
func TestBuildFilterTermSnapshotsNeverNil(t *testing.T) {
	for _, tc := range []struct {
		name   string
		filter *config.FirewallFilter
	}{
		{"nil filter", nil},
		{"zero terms", &config.FirewallFilter{Name: "F"}},
		{"all-nil terms", &config.FirewallFilter{Name: "F", Terms: []*config.FirewallFilterTerm{nil, nil}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := buildFilterTermSnapshots(tc.name, tc.filter, &config.Config{})
			if got == nil {
				t.Fatalf("buildFilterTermSnapshots(%s) = nil, want non-nil empty slice (#2214)", tc.name)
			}
			if len(got) != 0 {
				t.Fatalf("buildFilterTermSnapshots(%s) len = %d, want 0", tc.name, len(got))
			}
		})
	}
}

// End-to-end: the full ConfigSnapshot wire emitted for a config that hits BOTH
// triggers must contain `[]` (never null) for both keys. This is the wire-shape
// guarantee the Rust decoder relies on; a regression here reintroduces the
// whole-snapshot decode abort.
func TestSnapshotWireNoNullCollections2214(t *testing.T) {
	cfg := nat64NoPoolCfg()
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"EMPTY": {Name: "EMPTY"},
	}
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)

	if len(snap.NAT64) != 1 {
		t.Fatalf("snap.NAT64 = %d, want 1", len(snap.NAT64))
	}
	if len(snap.Filters) != 1 {
		t.Fatalf("snap.Filters = %d, want 1", len(snap.Filters))
	}

	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	wire := string(b)
	if strings.Contains(wire, `"pool_addresses":null`) {
		t.Fatal(`snapshot wire contains "pool_addresses":null — Rust Vec<String> rejects null and aborts the whole decode (#2214)`)
	}
	if strings.Contains(wire, `"terms":null`) {
		t.Fatal(`snapshot wire contains "terms":null — Rust Vec<FirewallTermSnapshot> rejects null and aborts the whole decode (#2214)`)
	}
	// Positive: the empty collections are present as [].
	if !strings.Contains(wire, `"pool_addresses":[]`) {
		t.Fatal(`snapshot wire missing "pool_addresses":[] for the empty-pool NAT64 rule (#2214)`)
	}
	// #18728: the zero-term filter's terms are the lone synthetic term.
	if !strings.Contains(wire, `"terms":`+implicitDiscardTermWire2214) {
		t.Fatal(`snapshot wire missing the zero-term filter's implicit-discard terms array (#2214/#18728)`)
	}
}
