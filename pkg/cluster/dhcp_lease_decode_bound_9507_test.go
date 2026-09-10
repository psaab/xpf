package cluster

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"testing"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #9507: the DHCP full-set lease decoder preallocated a count taken off the wire,
// clamped only to len(payload)/4, BEFORE validating a single record. A zero-length
// record is 4 wire bytes and decodes to a 168-byte zero-valued lease. One 16 MiB
// frame therefore drove about 672 MiB of lease slice per family, and the junk
// leases REPLACED the standby's peer set. Written before the fix; the defect
// cells are RED at base.

// allocBytes9507 returns the bytes allocated while running fn.
func allocBytes9507(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// zeroLengthCeilingFrame9507 is `count = len/4` followed by nothing but zero-length
// records: the shape the issue measured, at payloadBytes total.
func zeroLengthCeilingFrame9507(payloadBytes int) []byte {
	p := make([]byte, payloadBytes)
	binary.LittleEndian.PutUint32(p[:4], uint32(payloadBytes/4))
	return p // every record length prefix after the count is already 0
}

// frameOfRecords9507 frames raw records the way encodeDHCPLeasePayload does.
func frameOfRecords9507(recs [][]byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(recs)))
	for _, r := range recs {
		b = binary.LittleEndian.AppendUint32(b, uint32(len(r)))
		b = append(b, r...)
	}
	return b
}

// record2239Format9507 encodes a lease in the OLDEST format any peer has sent:
// the #2239 layout, which ends at the FQDN flags byte, before #5073 appended
// PreferredRemaining.
func record2239Format9507(t *testing.T, l dhcpserver.SyncLease) []byte {
	t.Helper()
	rec, err := encodeOneLease(l)
	if err != nil {
		t.Fatalf("FIXTURE: encodeOneLease: %v", err)
	}
	return rec[:len(rec)-4]
}

func TestDHCPZeroLengthCeilingFrameIsBoundedAndMalformed_9507(t *testing.T) {
	const payloadBytes = 1 << 20
	p := zeroLengthCeilingFrame9507(payloadBytes)
	var leases []dhcpserver.SyncLease
	var ok bool
	alloc := allocBytes9507(func() { leases, ok = decodeDHCPLeasePayload(p) })
	if limit := uint64(4 * payloadBytes); alloc > limit {
		t.Fatalf("#9507: decoding a %d-byte zero-length ceiling frame allocated %d bytes (%.1fx the frame, limit 4x). "+
			"At the 16 MiB frame cap that is the issue's ~672 MiB per family",
			payloadBytes, alloc, float64(alloc)/payloadBytes)
	}
	if ok {
		t.Fatalf("#9507: a frame of zero-length records decoded as COMPLETE (%d zero-valued leases); "+
			"no encoder produces a zero-length record, so it must be malformed", len(leases))
	}
}

func TestDHCPCeilingFrameDoesNotReplaceTheStoredSet_9507(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	legit := []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.0.5", HWAddress: "aa:bb:cc:dd:ee:01", Remaining: 3600, ValidLife: 3600},
		{Family: 4, Address: "10.0.0.6", HWAddress: "aa:bb:cc:dd:ee:02", Remaining: 3600, ValidLife: 3600},
	}
	const epoch = uint64(9507)
	ss.handleMessage(nil, syncMsgDHCPLeaseV4, appendFullSetSeq(encodeDHCPLeasePayload(legit), epoch, 1))
	if got := ss.PeerDHCPLeases4(); len(got) != 2 {
		t.Fatalf("FIXTURE: the legitimate set must be stored first, got %d leases", len(got))
	}
	ss.handleMessage(nil, syncMsgDHCPLeaseV4, appendFullSetSeq(zeroLengthCeilingFrame9507(1<<16), epoch, 2))
	got := ss.PeerDHCPLeases4()
	if len(got) != 2 || got[0].Address != "10.0.0.5" || got[1].Address != "10.0.0.6" {
		t.Fatalf("#9507: a zero-length ceiling frame REPLACED the stored peer set with %d leases", len(got))
	}
}

func TestDHCPRecordShorterThanAnyEncoderIsMalformed_9507(t *testing.T) {
	// The smallest real record is the #2239 form with a one-byte address: 36 bytes.
	// Its 35-byte prefix still frames a valid address, so only the length floor
	// can refuse it. This is the boundary cell for minDHCPLeaseRecordLen.
	minimal := record2239Format9507(t, dhcpserver.SyncLease{Family: 4, Address: "x"})
	if len(minimal) != 36 {
		t.Fatalf("FIXTURE: the minimal real record must be 36 bytes, got %d", len(minimal))
	}
	short := append([]byte(nil), minimal[:35]...)
	if _, ok := decodeDHCPLeasePayload(frameOfRecords9507([][]byte{short})); ok {
		t.Fatal("#9507: a 35-byte record, shorter than any real lease an encoder has emitted, decoded as complete")
	}
}

// An over-declared count on a legitimate frame is tolerated (#7175), but it must
// not size the allocation: the leases come from the records that actually arrived.
func TestDHCPOverDeclaredCountAllocatesOnlyWholeRecords_9507(t *testing.T) {
	var in []dhcpserver.SyncLease
	for i := 0; i < 1000; i++ {
		in = append(in, dhcpserver.SyncLease{Family: 4, Address: fmt.Sprintf("10.9.%d.%d", i>>8, i&0xff),
			HWAddress: "aa:bb:cc:dd:ee:ff", Hostname: fmt.Sprintf("h%d", i), ValidLife: 60, Remaining: 30})
	}
	p := encodeDHCPLeasePayload(in)
	binary.LittleEndian.PutUint32(p[:4], uint32(len(p)/4)) // the largest count the clamp admits
	var leases []dhcpserver.SyncLease
	var ok bool
	alloc := allocBytes9507(func() { leases, ok = decodeDHCPLeasePayload(p) })
	if !ok || len(leases) != len(in) {
		t.Fatalf("FIXTURE (#7175): an over-declared count on whole records must still decode (ok=%v, %d of %d)",
			ok, len(leases), len(in))
	}
	if limit := uint64(6 * len(p)); alloc > limit {
		t.Fatalf("#9507: an over-declared count sized the allocation: %d bytes for a %d-byte frame (%.1fx, limit 6x)",
			alloc, len(p), float64(alloc)/float64(len(p)))
	}
}

func TestDHCPEmptyAddressRecordIsMalformed_9507(t *testing.T) {
	rec, err := encodeOneLease(dhcpserver.SyncLease{Family: 4})
	if err != nil || len(rec) != 39 {
		t.Fatalf("FIXTURE: an all-empty current-format record must be 39 bytes, got %d (err %v)", len(rec), err)
	}
	if leases, ok := decodeDHCPLeasePayload(frameOfRecords9507([][]byte{rec})); ok {
		t.Fatalf("#9507: a record with no address decoded as a complete lease set (%d leases); "+
			"a DHCP lease without an address is not a lease", len(leases))
	}
}

// GUARD: the worst legitimately-formatted frame (minimal valid records, the #2239
// format with a one-byte address) allocates within a small multiple of its size.
func TestDHCPWorstCaseValidFrameAllocationIsBounded_9507(t *testing.T) {
	rec := record2239Format9507(t, dhcpserver.SyncLease{Family: 4, Address: "x"})
	n := (1 << 20) / (4 + len(rec))
	recs := make([][]byte, n)
	for i := range recs {
		recs[i] = rec
	}
	p := frameOfRecords9507(recs)
	var leases []dhcpserver.SyncLease
	var ok bool
	alloc := allocBytes9507(func() { leases, ok = decodeDHCPLeasePayload(p) })
	if !ok || len(leases) != n {
		t.Fatalf("FIXTURE: %d minimal valid records must decode completely (ok=%v, got %d)", n, ok, len(leases))
	}
	if limit := uint64(6 * len(p)); alloc > limit {
		t.Fatalf("#9507: a %d-byte frame of minimal valid records allocated %d bytes (%.1fx, limit 6x)",
			len(p), alloc, float64(alloc)/float64(len(p)))
	}
}

// CONTROL: the oldest record format any peer has sent still decodes, which is the
// rolling-upgrade floor the minimum-length rule must not cross.
func TestDHCPOldestPeerRecordFormatStillDecodes_9507(t *testing.T) {
	in := dhcpserver.SyncLease{Family: 4, Address: "10.1.2.3", SubnetID: 7, ValidLife: 600, Remaining: 300, State: 1}
	rec := record2239Format9507(t, in)
	leases, ok := decodeDHCPLeasePayload(frameOfRecords9507([][]byte{rec}))
	if !ok || len(leases) != 1 {
		t.Fatalf("a #2239-format record (%d bytes) must still decode completely (ok=%v, %d leases)", len(rec), ok, len(leases))
	}
	got := leases[0]
	if got.Address != in.Address || got.SubnetID != in.SubnetID || got.Remaining != in.Remaining ||
		got.PreferredRemaining != in.Remaining {
		t.Fatalf("#2239-format record decoded wrong: %+v", got)
	}
}

// CONTROL (load-bearing): a legitimate lease set as large as one sync frame can
// carry still decodes COMPLETELY. Without this, a bound tight enough to refuse the
// attack could also refuse a real standby's lease set, trading a DoS for an outage.
func TestDHCPValidMaximumSizeLeaseSetDecodesCompletely_9507(t *testing.T) {
	const frameCap = 16 * 1024 * 1024
	budget := frameCap - fullSetSeqTrailerLen9507(t)
	var leases []dhcpserver.SyncLease
	size := 4
	for i := 0; ; i++ {
		l := dhcpserver.SyncLease{
			Family: 4, Address: fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff),
			SubnetID: 1, ValidLife: 3600, Remaining: 1800, PreferredRemaining: 1800, State: 0,
			HWAddress: fmt.Sprintf("aa:bb:%02x:%02x:%02x:%02x", (i>>24)&0xff, (i>>16)&0xff, (i>>8)&0xff, i&0xff),
			ClientID:  fmt.Sprintf("01:aa:bb:%02x:%02x:%02x:%02x", (i>>24)&0xff, (i>>16)&0xff, (i>>8)&0xff, i&0xff),
			Hostname:  fmt.Sprintf("host-%d", i),
		}
		rec, err := encodeOneLease(l)
		if err != nil {
			t.Fatalf("FIXTURE: %v", err)
		}
		if size+4+len(rec) > budget {
			break
		}
		size += 4 + len(rec)
		leases = append(leases, l)
	}
	p := encodeDHCPLeasePayload(leases)
	if len(p) != size || len(p) > budget {
		t.Fatalf("FIXTURE: the set must fill but fit one frame: %d bytes, budget %d", len(p), budget)
	}
	out, ok := decodeDHCPLeasePayload(p)
	if !ok || len(out) != len(leases) {
		t.Fatalf("#9507 CONTROL: a legitimate %d-lease set (%d bytes, one full frame) did not decode completely "+
			"(ok=%v, got %d)", len(leases), len(p), ok, len(out))
	}
	if out[0] != leases[0] || out[len(out)-1] != leases[len(leases)-1] {
		t.Fatalf("#9507 CONTROL: the maximum-size set decoded with wrong contents at its ends")
	}
}

// fullSetSeqTrailerLen9507 measures the ordering trailer appendFullSetSeq adds, so
// the maximum-size control fits a frame the receiver actually accepts.
func fullSetSeqTrailerLen9507(t *testing.T) int {
	t.Helper()
	return len(appendFullSetSeq(nil, 1, 1))
}

// An address whose length runs past its own record frames as a lease but decodes
// to one with no address. It must refuse the set, not be retained as a lease.
func TestDHCPAddressOverrunningItsRecordIsMalformed_9507(t *testing.T) {
	rec := record2239Format9507(t, dhcpserver.SyncLease{Family: 4, Address: "10.0.0.1"})
	binary.LittleEndian.PutUint16(rec[1:], uint16(len(rec))) // address length > what the record holds
	if leases, ok := decodeDHCPLeasePayload(frameOfRecords9507([][]byte{rec})); ok {
		t.Fatalf("#9507: a record whose address overruns it decoded as a complete set (%d leases)", len(leases))
	}
}
