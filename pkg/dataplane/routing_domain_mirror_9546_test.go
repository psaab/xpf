package dataplane

import (
	"testing"
	"unsafe"
)

// #9546 — `SessionValue.RoutingDomain` must SURVIVE the BPF session mirror.
//
// HISTORY, because this file used to assert the opposite. As
// routing_domain_mirror_inert_9364_test.go it was #9364's TWO-SIDED guard: it
// passed while the on-map `session_value` ABI had no routing-domain slot —
// measured `100007 -> 0`, with TCPState and Timeout surviving the same round
// trip — and was worded to FAIL the day the slot appeared, so the ABI change
// could not land while the tree still claimed the domain was lost. It failed on
// the #9546 edit exactly as designed, naming itself, and is now inverted into the
// guard for the fix.
//
// Why the round trip is the right unit: every production batch delete sources its
// values from `store.ForEachV4` -> `BatchIterateSessions` -> `sessionValue()`, and
// the singular delete from `GetSessionV4` -> the same conversion. If the domain
// does not survive `toBPF().sessionValue()`, no delete path can name it, however
// correct the plumbing above it is — which is exactly how #9146 and #9364 were
// both inert.

func TestRoutingDomainSurvivesTheBPFSessionMirror9546(t *testing.T) {
	const tenant = uint32(100007)
	in := SessionValue{RoutingDomain: tenant, TCPState: 3, Timeout: 300}

	out := in.toBPF().sessionValue()

	// POSITIVE CONTROL in the same probe: if unrelated fields are lost too, the
	// round trip itself is broken and nothing below is attributable.
	if out.TCPState != in.TCPState || out.Timeout != in.Timeout {
		t.Fatalf("CONTROL FAILED: the round trip lost unrelated fields "+
			"(TCPState %d->%d, Timeout %d->%d)", in.TCPState, out.TCPState, in.Timeout, out.Timeout)
	}
	if out.RoutingDomain != tenant {
		t.Fatalf("#9546: RoutingDomain %d -> %d through the BPF mirror. Every value a "+
			"delete path reads back comes through this conversion, so the #9146 singular "+
			"and #9364 batch delete scoping are inert again", tenant, out.RoutingDomain)
	}
}

func TestRoutingDomainSurvivesTheBPFSessionMirrorV6_9546(t *testing.T) {
	const tenant = uint32(100008)
	in := SessionValueV6{RoutingDomain: tenant, TCPState: 3, Timeout: 300}

	out := in.toBPF().sessionValue()

	if out.TCPState != in.TCPState || out.Timeout != in.Timeout {
		t.Fatalf("CONTROL FAILED: the V6 round trip lost unrelated fields")
	}
	if out.RoutingDomain != tenant {
		t.Fatalf("#9546 V6: RoutingDomain %d -> %d through the BPF mirror. V6 has its own "+
			"struct and its own conversion pair, so it can regress on its own", tenant, out.RoutingDomain)
	}
}

// Every encoded value survives unchanged — including 0, which must stay 0.
// 0 is WIRE_ABSENT, the helper's "not stated" (a reverse-match row, or a value
// that predates the field); if the mirror turned it into anything else, a bare
// delete would suddenly name a domain.
func TestEveryEncodedDomainSurvivesTheMirror9546(t *testing.T) {
	for _, domain := range []uint32{0, 1, 100007, 999999, 4294967295} {
		if got := (SessionValue{RoutingDomain: domain}).toBPF().sessionValue().RoutingDomain; got != domain {
			t.Errorf("V4 domain %d came back as %d", domain, got)
		}
		if got := (SessionValueV6{RoutingDomain: domain}).toBPF().sessionValue().RoutingDomain; got != domain {
			t.Errorf("V6 domain %d came back as %d", domain, got)
		}
	}
}

// WHERE the field sits, in both types, and that they agree.
//
// The on-map offset is the one C and Rust also pin (144/192): append-after-the-
// ingress-pair is what keeps every pre-existing offset fixed. The wide type must
// hold the field at the SAME offset, because the shared-prefix invariant
// (TestSessionValueCarriesSyncOnlyGeneration) is only meaningful if the prefix is
// the same fields in the same places — a SessionValue that kept RoutingDomain in
// its sync-only tail would still convert correctly field-by-field, yet silently
// shift Generation away from the ABI boundary.
func TestRoutingDomainOffsets9546(t *testing.T) {
	for _, tc := range []struct {
		name      string
		got, want uintptr
	}{
		{"bpfSessionValue.RoutingDomain", unsafe.Offsetof(bpfSessionValue{}.RoutingDomain), conntrackRoutingDomainOffV4},
		{"bpfSessionValueV6.RoutingDomain", unsafe.Offsetof(bpfSessionValueV6{}.RoutingDomain), conntrackRoutingDomainOffV6},
		{"SessionValue.RoutingDomain (wide == on-map)", unsafe.Offsetof(SessionValue{}.RoutingDomain), unsafe.Offsetof(bpfSessionValue{}.RoutingDomain)},
		{"SessionValueV6.RoutingDomain (wide == on-map)", unsafe.Offsetof(SessionValueV6{}.RoutingDomain), unsafe.Offsetof(bpfSessionValueV6{}.RoutingDomain)},
	} {
		if tc.got != tc.want {
			t.Errorf("offsetof(%s) = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}
