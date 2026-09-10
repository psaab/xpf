package dataplane

import "testing"

// #9364 / #9546 — pin that `SessionValue.RoutingDomain` is DROPPED by the BPF
// session mirror, because that is what makes the whole delete-scoping family
// inert on the real path.
//
// WHY THIS CELL EXISTS. #9146 threaded the routing domain onto the SINGULAR
// delete wire and #9364 threads it onto the BATCH one. Both derive it from a
// `SessionValue` that came out of the mirror, and the mirror does not keep it:
// the BPF `session_value` ABI has no such field, so every value read back carries
// 0. Both fixes are therefore correct and currently unreachable with a non-zero
// domain. #9146's own acceptance cell has been reporting this on master since it
// landed — it only runs under CAP_BPF, so nobody saw it (#9337).
//
// This cell needs no privilege. It measures the conversion functions directly,
// which is the whole mechanism, so the fact stays visible in an ordinary run.
//
// IT IS TWO-SIDED, the `known_gap` shape. While the ABI lacks the field it passes
// and documents why the plumbing above it is inert; the day the field is added it
// FAILS, naming itself, so the ABI change cannot land while the tree still asserts
// the domain is lost. A cell that merely passed would leave #9364's plumbing
// looking permanently inert after it had come alive.
func TestRoutingDomainIsDroppedByTheBPFSessionMirror9364(t *testing.T) {
	const tenant = uint32(100007)
	in := SessionValue{RoutingDomain: tenant, TCPState: 3, Timeout: 300}

	out := in.toBPF().sessionValue()

	// POSITIVE CONTROL, in the same probe: neighbouring fields DO survive, so a
	// zero below is a property of RoutingDomain and not of a broken round trip.
	if out.TCPState != in.TCPState || out.Timeout != in.Timeout {
		t.Fatalf("CONTROL FAILED: the round trip lost unrelated fields too "+
			"(TCPState %d->%d, Timeout %d->%d) — this cell cannot attribute anything",
			in.TCPState, out.TCPState, in.Timeout, out.Timeout)
	}

	if out.RoutingDomain != 0 {
		t.Fatalf("#9364/#9546: SessionValue.RoutingDomain now SURVIVES the BPF mirror "+
			"(%d -> %d). That is the blocker this cell records, so its removal is good "+
			"news — but three things must be updated together or the tree now lies:\n"+
			"  1. this cell, which asserts the opposite;\n"+
			"  2. the inertness note on the #9364 batch plumbing in session_store.go;\n"+
			"  3. #9546, which should close, and #9146/#9364, whose fixes are live now.\n"+
			"Confirm with the privileged run: TestDeleteSessionItselfNamesTheDomainOnTheWire9146 "+
			"must pass under CAP_BPF, where it has been failing.",
			tenant, out.RoutingDomain)
	}
}

// The consequence, stated where a reader of the batch path will find it: every
// production caller of the batch delete sources its values from the mirror, so
// every one of them supplies domain 0 today.
//
// This is a DOCUMENTATION cell — it asserts the conversion, not the callers,
// because asserting the callers would need their whole fixtures. Its value is
// that the claim above sits next to a measurement rather than in a comment.
func TestEveryMirrorSourcedValueCarriesDomainZero9364(t *testing.T) {
	for _, domain := range []uint32{0, 1, 100007, 4294967295} {
		got := SessionValue{RoutingDomain: domain}.toBPF().sessionValue().RoutingDomain
		if got != 0 {
			t.Errorf("domain %d survived the mirror as %d — see the sibling cell", domain, got)
		}
	}
}
