package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestSyncApplyIdenticalRepushPreservesDistinctHistory12163 pins the #12163
// store contract: a persistent apply NACK must not churn rollback history.
//
// The daemon's configSyncReconcileLoop re-pushes the peer config every 30 s,
// and the #4957 converged shortcut requires ActiveApplied() — so a config
// whose apply keeps failing falls through to syncAndApply on EVERY tick.
// SyncApply promotes active BEFORE applyConfigLocked runs, so each failed
// retry re-pushes the identical text. Without dedup, every re-push evicts one
// distinct slot, and 50 ticks (~25 min) wipe the whole 50-slot ring: failover
// then has no rollback targets left.
//
// This fixture mirrors that storm at the store seam: seed three distinct
// configs, never stamp the applied marker (persistent NACK), then re-push the
// current text more times than the ring holds. The distinct predecessors must
// survive, and a later DIFFERENT config must still push (dedup only skips
// identical-text re-pushes).
func TestSyncApplyIdenticalRepushPreservesDistinctHistory12163(t *testing.T) {
	s := newTestStore(t)
	confA := "system {\n    host-name node-a-12163;\n}\n"
	confB := "system {\n    host-name node-b-12163;\n}\n"
	confC := "system {\n    host-name node-c-12163;\n}\n"
	for _, conf := range []string{confA, confB, confC} {
		if _, err := s.SyncApply(conf, nil); err != nil {
			t.Fatalf("SyncApply seed: %v", err)
		}
	}
	if s.ActiveApplied() {
		t.Fatal("fixture: promoted-but-unstamped sync must read not-applied (the NACK premise)")
	}
	before := len(s.ListHistory())

	// The NACK storm: re-push the CURRENT text more times than the ring
	// holds. 60 pushes into a 50-slot ring evicts every distinct entry
	// without dedup.
	for i := 0; i < 60; i++ {
		if _, err := s.SyncApply(confC, nil); err != nil {
			t.Fatalf("SyncApply identical re-push %d: %v", i, err)
		}
	}

	entries := s.ListHistory()
	for _, marker := range []string{"node-a-12163", "node-b-12163"} {
		found := false
		for _, e := range entries {
			if e != nil && e.Config != nil && strings.Contains(e.Config.Format(), marker) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("distinct history entry %q evicted by identical re-pushes; "+
				"rollback history must survive a persistent apply NACK", marker)
		}
	}
	if got := len(entries); got != before {
		t.Fatalf("identical re-pushes grew history: %d -> %d; want no growth "+
			"(each identical re-push must skip the history push)", before, got)
	}

	// A genuinely DIFFERENT config must still push (dedup is
	// identical-text only): the displaced C becomes the new head.
	confD := "system {\n    host-name node-d-12163;\n}\n"
	if _, err := s.SyncApply(confD, nil); err != nil {
		t.Fatalf("SyncApply distinct config: %v", err)
	}
	after := s.ListHistory()
	if len(after) != before+1 {
		t.Fatalf("distinct push history len = %d, want %d", len(after), before+1)
	}
	if after[0] == nil || after[0].Config == nil ||
		!strings.Contains(after[0].Config.Format(), "node-c-12163") {
		t.Fatalf("distinct push did not push the displaced config to the head")
	}
}

// TestSyncApplyBelowMinimumCleartextPushesHistory12163 pins the GLM round-1
// F1 edge: legacy cleartext below the slot minimum must NOT verify-equivalent
// against a valid verifier. Promotion installs the $xpf-invalid$ deny marker,
// so suppressing the push would leave the working verifier in NEITHER active
// NOR history. Reachable only via foreign/older peer software (own writes
// enforce min-runes), hence a dedicated regression, not a cleanliness nit.
func TestSyncApplyBelowMinimumCleartextPushesHistory12163(t *testing.T) {
	s := newTestStore(t)
	plain := "system {\n    host-name below-min-seed-12163;\n}\n"
	if _, err := s.SyncApply(plain, nil); err != nil {
		t.Fatalf("SyncApply plain seed: %v", err)
	}
	// Seed active with a VALID verifier of a short secret, pushed verbatim
	// (verifiers pass through hashing unchanged) — the foreign-peer shape.
	// The host-name matches the plain seed so ONLY the credential differs.
	verifier, err := config.HashAPIAuthSecret("short5")
	if err != nil {
		t.Fatalf("seed verifier: %v", err)
	}
	seed := "system {\n    host-name below-min-seed-12163;\n" +
		"    services {\n        web-management {\n" +
		"            api-auth {\n                expires 2099-01-01;\n" +
		"                user admin { password \"" + verifier + "\"; }\n" +
		"            }\n        }\n    }\n}\n"
	if _, err := s.SyncApply(seed, nil); err != nil {
		t.Fatalf("SyncApply seed: %v", err)
	}
	before := len(s.ListHistory())
	// Legacy re-push of the same short cleartext: below the 12-rune minimum,
	// so equivalence must NOT hold and the push must capture history.
	retry := "system {\n    host-name below-min-seed-12163;\n" +
		"    services {\n        web-management {\n" +
		"            api-auth {\n                expires 2099-01-01;\n" +
		"                user admin { password \"short5\"; }\n" +
		"            }\n        }\n    }\n}\n"
	if _, err := s.SyncApply(retry, nil); err != nil {
		t.Fatalf("SyncApply below-minimum retry: %v", err)
	}
	after := s.ListHistory()
	if len(after) != before+1 {
		t.Fatalf("below-minimum retry history len = %d, want %d "+
			"(must push: promotion installs the deny marker)", len(after), before+1)
	}
}

// TestSyncApplyBelowSlotMinimumKeyPushesHistory12163 pins the GLM
// F1-confirmation follow-up: the minimum gate is slot-aware. A 14-rune
// api-key cleartext (below the 16-rune key minimum, above the 12-rune
// password minimum) must NOT verify-equivalent — promotion installs the
// deny marker for the key slot too.
func TestSyncApplyBelowSlotMinimumKeyPushesHistory12163(t *testing.T) {
	s := newTestStore(t)
	key14 := "0123456789abcd"
	verifier, err := config.HashAPIAuthSecret(key14)
	if err != nil {
		t.Fatalf("seed verifier: %v", err)
	}
	mk := func(pw string) string {
		return "system {\n    host-name slotmin-12163;\n" +
			"    services {\n        web-management {\n" +
			"            api-auth {\n                expires 2099-01-01;\n" +
			"                api-key \"" + pw + "\";\n" +
			"            }\n        }\n    }\n}\n"
	}
	if _, err := s.SyncApply(mk(verifier), nil); err != nil {
		t.Fatalf("SyncApply seed: %v", err)
	}
	before := len(s.ListHistory())
	if _, err := s.SyncApply(mk(key14), nil); err != nil {
		t.Fatalf("SyncApply below-slot-minimum retry: %v", err)
	}
	if after := s.ListHistory(); len(after) != before+1 {
		t.Fatalf("below-slot-minimum retry history len = %d, want %d",
			len(after), before+1)
	}
}

// TestSyncApplyPasswordMinimumBandDedups12163 pins the GLM slot-confirmation
// MAJOR-1 fix: 12–15-rune passwords (at/above the 12-rune password minimum,
// below the 16-rune key minimum) must DEDUP on verifying retry — the slot
// gate must resolve the password keyword, not fall back to the key minimum.
func TestSyncApplyPasswordMinimumBandDedups12163(t *testing.T) {
	for _, pw := range []string{"0123456789ab", "0123456789abc", "0123456789abcde"} {
		verifier, err := config.HashAPIAuthSecret(pw)
		if err != nil {
			t.Fatalf("seed verifier: %v", err)
		}
		mk := func(val string) string {
			return "system {\n    host-name pwband-12163;\n" +
				"    services {\n        web-management {\n" +
				"            api-auth {\n                expires 2099-01-01;\n" +
				"                user admin { password \"" + val + "\"; }\n" +
				"            }\n        }\n    }\n}\n"
		}
		s := newTestStore(t)
		if _, err := s.SyncApply(mk(verifier), nil); err != nil {
			t.Fatalf("SyncApply seed: %v", err)
		}
		before := len(s.ListHistory())
		if _, err := s.SyncApply(mk(pw), nil); err != nil {
			t.Fatalf("SyncApply retry: %v", err)
		}
		if after := s.ListHistory(); len(after) != before {
			t.Fatalf("password-%d retry history len = %d, want %d (must dedup)",
				len(pw), len(after), before)
		}
	}
}
