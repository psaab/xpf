package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
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

// TestGRPCHitCountFilteredKeepsWildcardPairs covers the gRPC text hit-count
// surface. FAIL-ON-REVERT: restoring the exact-string skip drops wild-deny /
// wild-to-any / both-any-deny from the filtered output, so the assertions go
// RED.
func TestGRPCHitCountFilteredKeepsWildcardPairs(t *testing.T) {
	s := &Server{store: wildcardPairFilterStore(t)}

	var buf strings.Builder
	s.showPoliciesHitCount("from-zone trust to-zone untrust", &buf)
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
}

// TestGRPCDetailFilteredKeepsWildcardPairs covers the gRPC text detail
// surface. FAIL-ON-REVERT: restoring the exact-string skip drops the wildcard
// policy blocks, so the assertions go RED.
func TestGRPCDetailFilteredKeepsWildcardPairs(t *testing.T) {
	s := &Server{store: wildcardPairFilterStore(t)}

	var buf strings.Builder
	s.showPoliciesDetail("from-zone trust to-zone untrust", &buf)
	out := buf.String()

	for _, name := range []string{"Policy: exact-allow", "Policy: wild-to-any", "Policy: wild-deny", "Policy: both-any-deny", "Policy: open-global"} {
		if !strings.Contains(out, name) {
			t.Fatalf("filtered detail dropped %q (wildcard stanza enforced for trust->untrust — #12094 regression):\n%s", name, out)
		}
	}
	if strings.Contains(out, "Policy: off-pair") {
		t.Fatalf("filtered detail leaked an unrelated pair (dmz->untrust):\n%s", out)
	}
	assertPolicyOrder(t, out, []string{"Policy: exact-allow", "Policy: wild-to-any", "Policy: wild-deny", "Policy: both-any-deny", "Policy: open-global"})
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
