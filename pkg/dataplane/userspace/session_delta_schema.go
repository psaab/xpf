package userspace

import (
	"hash/fnv"
	"sort"
	"strings"
)

// #7194: the Go half of the DERIVED session-open delta schema identity.
//
// The Rust half is userspace-dp/src/protocol/session_delta_schema.rs. The two
// MUST produce the same u64 for the same wire schema, and they are asserted to
// AGREE rather than either being pinned to a literal — a literal would encode
// which side is trusted, and #7457 is the case in this tree where the side
// everyone assumed correct was the broken one.
//
// Canonical form (both sides): wire names, sorted ascending as byte strings,
// joined with "\n", no trailing newline; FNV-1a/64 over those bytes.
//
// WHY DERIVED. ConfigSnapshotProtocolVersion gates the config snapshot; the
// session-delta schema had no identity at all. Five fields (#5865) and
// rt_flow_session_id (#5212 -> #6312) each drifted between the two transports
// and shipped, because there was no version to bump and nothing computed one.
// A hand-maintained integer would inherit exactly that failed discipline. This
// is computed from the struct, so adding, removing or renaming a wire field
// changes it whether or not anyone remembers.

// NOTE ON PACKAGE PLACEMENT. The wire-name EXTRACTION
// (wireschema.WireNamesOf, #17137) lives in the
// pkg/wireschema package, not here, because it
// needs `reflect` and the #1476 retirement-boundary canary
// (TestUserspaceManagerDoesNotImportReflectOrUnsafe) forbids reflection
// anywhere under this package (the walk is recursive) — reflection is
// exactly how an entry-program canary would be bypassed. pkg/wireschema
// is outside that tree, reflect-allowed, and holds the ONLY production Go
// extractor. The canonicalisation and hashing below are pure functions
// over a name list, so they stay next to the wire types they describe.

// SessionDeltaSchemaCanonicalOf is the exact string the fingerprint is taken
// over: names sorted ascending as byte strings, joined with "\n", no trailing
// newline. Exposed separately from the hash so a mismatch can be DIFFED — two
// unequal u64s tell you that the schemas differ and nothing about how.
func SessionDeltaSchemaCanonicalOf(names []string) string {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	return strings.Join(sorted, "\n")
}

// SessionDeltaSchemaFingerprintOf hashes a wire-name set. 0 is reserved for
// "not advertised" and is returned only for an empty schema, which is itself a
// fail-closed condition.
func SessionDeltaSchemaFingerprintOf(names []string) uint64 {
	canonical := SessionDeltaSchemaCanonicalOf(names)
	if canonical == "" {
		return 0
	}
	return fnv1a64OfString(canonical)
}

// SessionDeltaSchemaVerdict is the three-state result of comparing a helper's
// advertised fingerprint against this binary's.
//
// Three states, not two, deliberately — mirroring noHelperVersionObservedLocked
// (#1960). Collapsing "never advertised" into "mismatch" would refuse HA sync
// against a helper that predates the field, which is a brick, not a fence.
type SessionDeltaSchemaVerdict int

const (
	// SessionDeltaSchemaUnknown: the helper advertises nothing (0). Permit and
	// defer — an older helper is fenced by the existing snapshot-protocol
	// gates, not by this one.
	SessionDeltaSchemaUnknown SessionDeltaSchemaVerdict = iota
	// SessionDeltaSchemaMatch: advertised and equal. Proceed.
	SessionDeltaSchemaMatch
	// SessionDeltaSchemaMismatch: advertised and DIFFERENT. Fail closed — the
	// running helper's delta schema is not this binary's, so a decoded record
	// may carry a zero that means "field not carried" rather than "no value",
	// and a zero installed as identity is the #5865 failure mode.
	SessionDeltaSchemaMismatch
)

func (v SessionDeltaSchemaVerdict) String() string {
	switch v {
	case SessionDeltaSchemaMatch:
		return "match"
	case SessionDeltaSchemaMismatch:
		return "mismatch"
	default:
		return "unknown"
	}
}

// CompareSessionDeltaSchema classifies a helper-advertised fingerprint.
// The reason string is for the operator-visible log/error; it names what the
// consequence is, not merely that two numbers differ.
func CompareSessionDeltaSchema(advertised, local uint64) (SessionDeltaSchemaVerdict, string) {
	switch {
	case advertised == 0:
		return SessionDeltaSchemaUnknown,
			"helper advertises no session-delta schema fingerprint (predates #7194) — permitted; " +
				"the snapshot-protocol gates still fence a helper that is genuinely too old"
	case advertised == local:
		return SessionDeltaSchemaMatch, "helper session-delta schema matches this binary"
	default:
		return SessionDeltaSchemaMismatch,
			"helper session-delta schema differs from this binary — a synced session could " +
				"install a zero standing in for a field the helper does not carry (policy " +
				"attribution, app timeout, NAT64), which is indistinguishable from a real zero " +
				"at the consumer"
	}
}

// fnv1a64OfString is the hash both languages implement. It is checked against
// the PUBLISHED FNV-1a/64 vectors rather than against the Rust side's output. Each language asserting the spec independently is what makes the two
// agree without either being pinned to the other — pinning one to the other's
// number would encode which implementation is trusted.
func fnv1a64OfString(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}
