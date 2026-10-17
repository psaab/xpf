package cluster

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #14638: every IdleLeaseWire field must survive the cluster codec.
// Reflection-driven so a future field added to IdleLeaseWire but not to the
// codec reds here instead of silently zeroing on the standby.
func TestPersistentNatLeaseDeterministicFieldsSurviveClusterCodec14638(t *testing.T) {
	scope := uint32(7)
	egress := uint32(11)
	in := userspace.IdleLeaseWire{
		Pool:                       "nat64-deterministic-0",
		Protocol:                   6,
		SrcIP:                      "2001:db8::1",
		SrcPort:                    40000,
		RoutingScope:               &scope,
		EgressScope:                &egress,
		RemoteIP:                   "8.8.8.8",
		RemotePort:                 443,
		PermitAnyRemote:            false,
		PermittedRemotes:           []userspace.PersistentNatRemote{{IP: "8.8.8.8", Port: 443}},
		TranslatedIP:               "203.0.113.1",
		TranslatedPort:             1024,
		AddressOnly:                false,
		Deterministic:              true,
		DeterministicMode:          2,
		DeterministicBlockSize:     32,
		DeterministicBlocksPerIP:   2,
		DeterministicHostPrefixLen: 32,
		DeterministicHostBase:      "2001:db8::",
		DeterministicHostCount:     2,
		RemainingNs:                270_000_000_000,
		TimeoutNs:                  300_000_000_000,
	}
	// Batch path (the production Queue/decode path shape) — deterministic layout.
	batch := userspace.PersistentNatLeaseBatch{
		OriginID:   "0123456789abcdef0123456789abcdef",
		Generation: 9,
		Leases:     []userspace.IdleLeaseWire{in},
	}
	payload, err := encodePersistentNatLeaseBatchPayload(batch)
	if err != nil {
		t.Fatalf("encode batch: %v", err)
	}
	gotBatch, ok := decodePersistentNatLeaseBatchPayloadDeterministic(payload)
	if !ok {
		t.Fatalf("deterministic batch failed to decode completely")
	}
	if len(gotBatch.Leases) != 1 {
		t.Fatalf("decoded leases = %d, want 1", len(gotBatch.Leases))
	}
	assertEveryFieldEqual14638(t, in, gotBatch.Leases[0])
	// The legacy decoder must reject the deterministic layout (strict
	// off==len), proving the version gate is load-bearing.
	if _, ok := decodePersistentNatLeaseBatchPayload(payload); ok {
		t.Fatal("legacy decoder accepted deterministic-layout batch; silent append would be unsafe")
	}

	// Payload path.
	out, ok := decodePersistentNatLeasePayloadDeterministic(encodePersistentNatLeasePayloadDeterministic([]userspace.IdleLeaseWire{in}))
	if !ok || len(out) != 1 {
		t.Fatalf("payload round-trip ok=%v n=%d", ok, len(out))
	}
	assertEveryFieldEqual14638(t, in, out[0])

	// Mode-1 (V4) deterministic identity must also survive.
	v4 := in
	v4.Pool = "det-v4"
	v4.SrcIP = "100.64.0.1"
	v4.DeterministicMode = 1
	v4.DeterministicHostPrefixLen = 0
	v4.DeterministicHostBase = "100.64.0.0"
	v4.DeterministicHostCount = 1024
	v4.DeterministicBlockSize = 512
	v4.DeterministicBlocksPerIP = 126
	out, ok = decodePersistentNatLeasePayloadDeterministic(encodePersistentNatLeasePayloadDeterministic([]userspace.IdleLeaseWire{v4}))
	if !ok || len(out) != 1 {
		t.Fatalf("v4 payload round-trip ok=%v n=%d", ok, len(out))
	}
	assertEveryFieldEqual14638(t, v4, out[0])
}

// #14638: wire-level gate — a deterministic batch queued through
// QueuePersistentNatLeaseBatch must arrive at the peer callback with its
// identity intact, and a legacy-layout batch must be rejected under the
// deterministic type (and vice versa).
func TestPersistentNatLeaseDeterministicWireGate14638(t *testing.T) {
	lease := sampleIdleLease()
	lease.Pool = "nat64-deterministic-0"
	lease.SrcIP = "2001:db8::1"
	lease.Deterministic = true
	lease.DeterministicMode = 2
	lease.DeterministicBlockSize = 32
	lease.DeterministicBlocksPerIP = 2
	lease.DeterministicHostPrefixLen = 32
	lease.DeterministicHostBase = "2001:db8::"
	lease.DeterministicHostCount = 2
	batch := sampleIdleLeaseBatch11486(lease)

	receiver := &SessionSync{}
	var got userspace.PersistentNatLeaseBatch
	sets := 0
	receiver.OnPersistentNatLeasesReceived = func(b userspace.PersistentNatLeaseBatch) {
		sets++
		got = b
	}
	payload, err := encodePersistentNatLeaseBatchPayload(batch)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	receiver.handleMessage(nil, syncMsgPersistentNatLeaseDeterministic, appendFullSetSeq(payload, 1, 1))
	if sets != 1 || len(got.Leases) != 1 {
		t.Fatalf("deterministic-type frame delivered sets=%d leases=%d", sets, len(got.Leases))
	}
	if !equalIdleLeaseWire(got.Leases[0], lease) {
		t.Fatalf("wire-delivered lease = %+v, want %+v", got.Leases[0], lease)
	}
	// Same bytes under the legacy type must be rejected, not stripped.
	receiver2 := &SessionSync{}
	sets2 := 0
	receiver2.OnPersistentNatLeasesReceived = func(userspace.PersistentNatLeaseBatch) { sets2++ }
	receiver2.handleMessage(nil, syncMsgPersistentNatLeaseGeneration, appendFullSetSeq(payload, 1, 1))
	if sets2 != 0 {
		t.Fatalf("legacy type accepted deterministic-layout batch (sets=%d)", sets2)
	}
	// Legacy bytes under the deterministic type must be rejected.
	legacyPayload := encodeTestLeaseBatch11486(t, sampleIdleLeaseBatch11486(sampleIdleLease()))
	receiver3 := &SessionSync{}
	sets3 := 0
	receiver3.OnPersistentNatLeasesReceived = func(userspace.PersistentNatLeaseBatch) { sets3++ }
	receiver3.handleMessage(nil, syncMsgPersistentNatLeaseDeterministic, appendFullSetSeq(legacyPayload, 1, 1))
	if sets3 != 0 {
		t.Fatalf("deterministic type accepted legacy-layout batch (sets=%d)", sets3)
	}
}

func assertEveryFieldEqual14638(t *testing.T, want, got userspace.IdleLeaseWire) {
	t.Helper()
	wv := reflect.ValueOf(want)
	gv := reflect.ValueOf(got)
	typ := wv.Type()
	for i := range wv.NumField() {
		name := typ.Field(i).Name
		wf := wv.Field(i)
		gf := gv.Field(i)
		if wf.Kind() == reflect.Pointer {
			if (wf.IsNil()) != (gf.IsNil()) {
				t.Errorf("field %s nil mismatch: want nil=%v got nil=%v", name, wf.IsNil(), gf.IsNil())
				continue
			}
			if !wf.IsNil() && wf.Elem().Interface() != gf.Elem().Interface() {
				t.Errorf("field %s = %v, want %v", name, gf.Elem(), wf.Elem())
			}
			continue
		}
		if !reflect.DeepEqual(wf.Interface(), gf.Interface()) {
			t.Errorf("field %s = %#v, want %#v (dropped by cluster codec #14638)", name, gf.Interface(), wf.Interface())
		}
	}
}

// #14638: a new-format deterministic record must be rejected by an old-layout
// decoder view — i.e. trailing bytes are not silently ignored. This pins that
// the version-gated type (not in-place append) is required: feeding a v2 record
// payload to decodeOnePersistentNatLease (old strict off==len semantics would
// have rejected extra bytes) — here we assert the new decoder rejects a record
// with garbage appended, so a future silent-append cannot pass.
func TestPersistentNatLeaseDeterministicTrailingGarbageRejected14638(t *testing.T) {
	lease := sampleIdleLease()
	lease.Deterministic = true
	lease.DeterministicMode = 2
	lease.DeterministicBlockSize = 32
	lease.DeterministicBlocksPerIP = 2
	lease.DeterministicHostPrefixLen = 32
	lease.DeterministicHostBase = "2001:db8::"
	lease.DeterministicHostCount = 2
	rec, err := encodeOnePersistentNatLeaseLayout(lease, true)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, ok := decodeOnePersistentNatLeaseDeterministic(append(rec, 0xFF)); ok {
		t.Fatal("decoder accepted trailing garbage after deterministic record")
	}
	if _, ok := decodeOnePersistentNatLease(rec); ok {
		t.Fatal("legacy decoder accepted deterministic record")
	}
	if _, err := encodeOnePersistentNatLease(lease); err == nil {
		t.Fatal("legacy encoder silently stripped deterministic identity")
	}
}
