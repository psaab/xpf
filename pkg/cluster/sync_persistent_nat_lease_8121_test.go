package cluster

import (
	"math"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

func persistentNatLeaseScope(v uint32) *uint32 {
	return &v
}

func equalIdleLeaseWire(a, b userspace.IdleLeaseWire) bool {
	if a.RoutingScope == nil || b.RoutingScope == nil {
		return a.RoutingScope == b.RoutingScope && a.Pool == b.Pool &&
			a.Protocol == b.Protocol && a.SrcIP == b.SrcIP &&
			a.SrcPort == b.SrcPort && a.RemoteIP == b.RemoteIP &&
			a.RemotePort == b.RemotePort && a.TranslatedIP == b.TranslatedIP &&
			a.TranslatedPort == b.TranslatedPort && a.AddressOnly == b.AddressOnly &&
			a.RemainingNs == b.RemainingNs && a.TimeoutNs == b.TimeoutNs
	}
	as, bs := *a.RoutingScope, *b.RoutingScope
	a.RoutingScope, b.RoutingScope = nil, nil
	return as == bs && a == b
}

func sampleIdleLease() userspace.IdleLeaseWire {
	return userspace.IdleLeaseWire{
		Pool:           "P",
		Protocol:       6,
		SrcIP:          "10.0.61.50",
		SrcPort:        40000,
		RoutingScope: persistentNatLeaseScope(7),
		RemoteIP:       "8.8.8.8",
		RemotePort:     443,
		TranslatedIP:   "203.0.113.1",
		TranslatedPort: 1024,
		AddressOnly:    false,
		RemainingNs:    270_000_000_000,
		TimeoutNs:      300_000_000_000,
	}
}

// #8121: every field survives the wire. A field silently dropped here becomes a
// zero on the standby — and a zero `RemainingNs` is not an obvious failure, it
// is a lease the receiver discards, so the symptom would be "the feature does
// nothing" rather than a decode error.
func TestPersistentNatLeasePayload_RoundTrip(t *testing.T) {
	in := []userspace.IdleLeaseWire{
		sampleIdleLease(),
		{
			// permit-any-remote-host: an EMPTY remote must stay empty rather
			// than round-tripping into an address.
			Pool:           "Q",
			Protocol:       17,
			SrcIP:          "2001:db8::1",
			SrcPort:        5000,
			RoutingScope:   persistentNatLeaseScope(0),
			TranslatedIP:   "203.0.113.9",
			TranslatedPort: 2048,
			AddressOnly:    true,
			RemainingNs:    1,
			TimeoutNs:      60_000_000_000,
		},
	}
	out, ok := decodePersistentNatLeasePayload(encodePersistentNatLeasePayload(in))
	if !ok {
		t.Fatalf("a well-formed payload must decode completely")
	}
	if len(out) != len(in) {
		t.Fatalf("record count: got %d want %d", len(out), len(in))
	}
	for i := range in {
		if !equalIdleLeaseWire(out[i], in[i]) {
			t.Errorf("record %d round-trip mismatch:\n got %+v\nwant %+v", i, out[i], in[i])
		}
	}
}

// #4892 shape: a string field longer than the uint16 length prefix can describe
// must DROP that record, never narrow the prefix. A wrapped length misframes the
// peer's decode, so every record after it is read from the wrong offset — one
// unencodable lease would corrupt the whole set.
func TestPersistentNatLeaseEncode_OversizedFieldDropsOnlyThatRecord(t *testing.T) {
	good := sampleIdleLease()
	oversized := sampleIdleLease()
	oversized.Pool = strings.Repeat("p", math.MaxUint16+1)

	out, ok := decodePersistentNatLeasePayload(
		encodePersistentNatLeasePayload([]userspace.IdleLeaseWire{good, oversized, good}),
	)
	if !ok {
		t.Fatalf("dropping a record must leave the payload self-consistent, not truncated")
	}
	if len(out) != 2 {
		t.Fatalf("the oversized record must be dropped and the others kept: got %d records", len(out))
	}
	for i, rec := range out {
		if !equalIdleLeaseWire(rec, good) {
			t.Errorf("surviving record %d was corrupted by the dropped one: %+v", i, rec)
		}
	}
	// CONTROL: the same three records with a legal Pool encode to THREE, so the
	// count above is caused by the oversize and not by the fixture.
	oversized.Pool = "R"
	ctl, ok := decodePersistentNatLeasePayload(
		encodePersistentNatLeasePayload([]userspace.IdleLeaseWire{good, oversized, good}),
	)
	if !ok || len(ctl) != 3 {
		t.Fatalf("control: a legal three-record set must encode to 3, got %d ok=%v", len(ctl), ok)
	}
}

// #7175 discipline: a full-set push REPLACES the peer's set, so a truncated
// payload must report INCOMPLETE. Returning a prefix as if it were the whole
// set would silently delete every lease past the truncation point.
func TestPersistentNatLeasePayload_TruncationReportsIncomplete(t *testing.T) {
	full := encodePersistentNatLeasePayload([]userspace.IdleLeaseWire{
		sampleIdleLease(), sampleIdleLease(),
	})
	// CONTROL: the untruncated payload decodes completely, so each failure
	// below is caused by the cut and not by a malformed fixture.
	if _, ok := decodePersistentNatLeasePayload(full); !ok {
		t.Fatalf("control: the full payload must decode completely")
	}
	for cut := 1; cut < len(full); cut++ {
		if _, ok := decodePersistentNatLeasePayload(full[:cut]); ok {
			t.Fatalf("a payload truncated to %d/%d bytes must report incomplete", cut, len(full))
		}
	}
}

func TestPersistentNatLeaseEncodeRejectsMissingScope10018(t *testing.T) {
	legacy := sampleIdleLease()
	legacy.RoutingScope = nil

	out, ok := decodePersistentNatLeasePayload(
		encodePersistentNatLeasePayload([]userspace.IdleLeaseWire{legacy, sampleIdleLease()}),
	)
	if !ok {
		t.Fatal("a dropped legacy record must not make the remaining scoped set incomplete")
	}
	if len(out) != 1 || out[0].RoutingScope == nil || *out[0].RoutingScope != 7 {
		t.Fatalf("missing-scope record was not dropped fail-closed: %+v", out)
	}
}

// #10018 migration fence: a pre-v25 type-38 frame is ignored as a whole. It
// must not invoke the receive callback and must not advance the scoped
// sequence guard, because doing either would let an unscoped high-water mark
// suppress a later scoped type-39 set.
func TestPersistentNatLeaseSyncIgnoresRetiredUnscopedType10018(t *testing.T) {
	ss := &SessionSync{}
	sets := 0
	ss.OnPersistentNatLeasesReceived = func([]userspace.IdleLeaseWire) { sets++ }
	payload := appendFullSetSeq(
		encodePersistentNatLeasePayload([]userspace.IdleLeaseWire{sampleIdleLease()}),
		9000,
		99,
	)

	ss.handleMessage(nil, syncMsgPersistentNatLease, payload)
	if sets != 0 {
		t.Fatalf("retired unscoped type-38 frame invoked callback %d times", sets)
	}

	// A scoped frame with a deliberately lower sequence must still apply. If
	// the retired arm touched persistentNatLeaseRecvSeq, this would be dropped.
	ss.handleMessage(nil, syncMsgPersistentNatLeaseScoped,
		appendFullSetSeq(encodePersistentNatLeasePayload([]userspace.IdleLeaseWire{
			sampleIdleLease(),
		}), 1, 1))
	if sets != 1 {
		t.Fatalf("scoped type-39 frame was suppressed by retired type-38 sequence state; sets=%d", sets)
	}
}

func TestPersistentNatLeaseMalformedSetDoesNotAdvanceSequence10018(t *testing.T) {
	ss := &SessionSync{}
	sets := 0
	ss.OnPersistentNatLeasesReceived = func([]userspace.IdleLeaseWire) { sets++ }

	// A high-sequence malformed full set must be retained as no-op, not become
	// the high-water mark that blocks a later valid lower-sequence set.
	ss.handleMessage(nil, syncMsgPersistentNatLeaseScoped,
		appendFullSetSeq([]byte{1, 2, 3}, 9000, 99))
	ss.handleMessage(nil, syncMsgPersistentNatLeaseScoped,
		appendFullSetSeq(encodePersistentNatLeasePayload([]userspace.IdleLeaseWire{
			sampleIdleLease(),
		}), 1, 1))
	if sets != 1 {
		t.Fatalf("valid lower-sequence set was suppressed after malformed high-sequence input; sets=%d", sets)
	}
}
