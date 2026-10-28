package userspace

import (
	"sort"
	"strings"
	"testing"
)

// #7194: the DERIVED schema fingerprint, and its agreement with the Rust half.
//
// FAIL-ON-REVERT: drop the reflection over json tags and the fingerprint stops
// tracking the wire; break the canonical form and the cross-language agreement
// cell reds; widen CompareSessionDeltaSchema's unknown arm and the fail-closed
// cell reds.

// Both languages are pinned to the PUBLISHED FNV-1a/64 vectors, never to each
// other's output. Pinning one to the other would encode which implementation is
// trusted — and #7457 in this tree is the case where the side everyone assumed
// correct was the broken one.
func TestFNV1aMatchesThePublishedVectors7194(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint64
	}{
		{"", 0xcbf29ce484222325},
		{"a", 0xaf63dc4c8601ec8c},
		{"foobar", 0x85944171f73967e8},
	} {
		if got := fnv1a64OfString(tc.in); got != tc.want {
			t.Errorf("fnv1a64(%q) = %#x, want %#x", tc.in, got, tc.want)
		}
	}
}

// goSchemaNames7194 reuses the SINGLE production extractor
// (wireschema.WireNamesOf, via goWireNames7194) rather than
// adding a second one — two extractors of the same thing is the disease
// #7194 is treating, and #17137 removed the last unguarded copies.
func goSchemaNames7194(t *testing.T) []string {
	t.Helper()
	m := goWireNames7194(t)
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func TestSessionDeltaSchemaCanonicalFormIsSortedAndNewlineJoined7194(t *testing.T) {
	canonical := SessionDeltaSchemaCanonicalOf(goSchemaNames7194(t))
	parts := strings.Split(canonical, "\n")
	sorted := append([]string(nil), parts...)
	sort.Strings(sorted)
	for i := range parts {
		if parts[i] != sorted[i] {
			t.Fatalf("canonical form must be sorted; got %v", parts)
		}
	}
	if strings.HasSuffix(canonical, "\n") {
		t.Error("canonical form must not end with a newline")
	}
	// Anti-vacuity: an empty or truncated reflection must not be able to report
	// a confident fingerprint. Mirrors the parity guard's floor.
	if len(parts) < 35 {
		t.Errorf("expected the full session-delta schema, got %d names: %v", len(parts), parts)
	}
	if SessionDeltaSchemaFingerprintOf(goSchemaNames7194(t)) == 0 {
		t.Error("fingerprint must never be 0 for a real schema — 0 is reserved for not-advertised")
	}
}

// The agreement, asserted rather than assumed. The fingerprint the RUST source
// would produce is recomputed here from the same brace-counted extraction the
// #8043 guard uses, and must equal the one Go derives from its own struct.
//
// This is what makes the two halves one schema rather than two that happen to
// match: if a field is added to either side alone, this reds — and unlike a
// pinned literal, neither side is designated the source of truth.
func TestSessionDeltaSchemaAgreesAcrossLanguages7194(t *testing.T) {
	rust := rustWireNames7194(t)
	rustNames := make([]string, 0, len(rust))
	for n := range rust {
		rustNames = append(rustNames, n)
	}
	sort.Strings(rustNames)

	if len(rustNames) < 35 {
		t.Fatalf("rust extraction returned %d names — too few to compare (truncated?)", len(rustNames))
	}

	rustFP := SessionDeltaSchemaFingerprintOf(rustNames)
	goFP := SessionDeltaSchemaFingerprintOf(goSchemaNames7194(t))
	if rustFP != goFP {
		t.Errorf("session-delta schema fingerprints disagree:\n  rust: %#x\n  go:   %#x\n"+
			"  rust names: %v\n  go names:   %v",
			rustFP, goFP, rustNames, goSchemaNames7194(t))
	}
}

// Three states, and the middle one is the whole point: a helper that advertises
// NOTHING must be permitted, not refused. Collapsing unknown into mismatch
// would brick HA against an older helper.
func TestSessionDeltaSchemaVerdictIsThreeState7194(t *testing.T) {
	local := SessionDeltaSchemaFingerprintOf(goSchemaNames7194(t))

	if v, _ := CompareSessionDeltaSchema(0, local); v != SessionDeltaSchemaUnknown {
		t.Errorf("advertised 0 must be Unknown (permit/defer), got %v", v)
	}
	if v, _ := CompareSessionDeltaSchema(local, local); v != SessionDeltaSchemaMatch {
		t.Errorf("advertised == local must be Match, got %v", v)
	}
	// A value that is neither 0 nor local. Deliberately not a "nearby" number:
	// it must not be one the gate could fall back to.
	if v, _ := CompareSessionDeltaSchema(local^0x5555_5555_5555_5555, local); v != SessionDeltaSchemaMismatch {
		t.Errorf("a different advertised fingerprint must be Mismatch, got %v", v)
	}
}

// The mismatch reason must name the CONSEQUENCE, not merely that two numbers
// differ — an operator reading it has to know that HA sync is being withheld
// and why that is preferable to proceeding.
func TestSessionDeltaSchemaMismatchReasonNamesTheConsequence7194(t *testing.T) {
	local := SessionDeltaSchemaFingerprintOf(goSchemaNames7194(t))
	_, reason := CompareSessionDeltaSchema(local^1, local)
	for _, want := range []string{"zero", "policy"} {
		if !strings.Contains(reason, want) {
			t.Errorf("mismatch reason should explain the zero-standing-in-for-absent hazard (missing %q): %s", want, reason)
		}
	}
}
