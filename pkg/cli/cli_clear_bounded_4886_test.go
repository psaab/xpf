package cli

// #4886 A (CLI half): the on-box filtered session clear used to snapshot EVERY
// matching forward key + its reverse/DNAT companions (v4 then v6) into growing
// slices before deleting, so a broad filtered clear on a multi-million-entry
// table allocated O(matches) up front and could OOM the in-process daemon before
// making progress. It now collects at most cliClearFilteredBatch keys, deletes
// that chunk, and resumes (cursor primary; bounded rescan fallback), peak
// O(batch). The gRPC half was already bounded by #5454.
//
// FAIL-ON-REVERT: restoring the snapshot-all path (collect every matching key
// before deleting) stops calling cliClearBatchObserver and collects a single
// len==matches slice, so the bounded-chunk assertions below (observer fired,
// every chunk <= batch, multi-chunk) go RED.

import (
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/psaab/xpf/pkg/dataplane"
)

// orderedClearDP is an in-insertion-order, cursor-honoring, removing v4 session
// store, so the bounded cursor clear can be driven over multiple chunks with a
// small cliClearFilteredBatch. IterateSessionsFrom yields keys STRICTLY AFTER
// the cursor (exclusive), matching *dataplane.Manager.IterateSessionsFrom, and
// skips already-deleted keys. Embeds *dataplane.Manager for the rest of
// cliRuntime.
type orderedClearDP struct {
	*dataplane.Manager
	keys    []dataplane.SessionKey
	vals    map[dataplane.SessionKey]dataplane.SessionValue
	deleted map[dataplane.SessionKey]bool
	nDelete int
}

func (d *orderedClearDP) IsLoaded() bool { return true }

func (d *orderedClearDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for _, k := range d.keys {
		if d.deleted[k] {
			continue
		}
		if !fn(k, d.vals[k]) {
			break
		}
	}
	return nil
}

func (d *orderedClearDP) IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	start := 0
	if cursor != nil {
		for i, k := range d.keys {
			if k == *cursor {
				start = i + 1 // exclusive: yield keys AFTER the cursor
				break
			}
		}
	}
	for _, k := range d.keys[start:] {
		if d.deleted[k] {
			continue
		}
		if !fn(k, d.vals[k]) {
			break
		}
	}
	return nil
}

func (d *orderedClearDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (d *orderedClearDP) IterateSessionsV6From(*dataplane.SessionKeyV6, func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (d *orderedClearDP) DeleteSession(key dataplane.SessionKey) error {
	if d.deleted[key] {
		return ebpf.ErrKeyNotExist // already gone: benign (addExceptNotFound)
	}
	d.deleted[key] = true
	d.nDelete++
	return nil
}

func (d *orderedClearDP) DeleteSessionV6(dataplane.SessionKeyV6) error { return nil }
func (d *orderedClearDP) DeleteDNATEntry(dataplane.DNATKey) error      { return nil }
func (d *orderedClearDP) DeleteDNATEntryV6(dataplane.DNATKeyV6) error  { return nil }

type protocolClearDP struct {
	*dataplane.Manager
	sessions map[dataplane.SessionKey]dataplane.SessionValue
	deleted  []dataplane.SessionKey
}

func (d *protocolClearDP) IsLoaded() bool { return true }

func (d *protocolClearDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for k, v := range d.sessions {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (d *protocolClearDP) IterateSessionsFrom(_ *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return d.IterateSessions(fn)
}

func (d *protocolClearDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (d *protocolClearDP) IterateSessionsV6From(*dataplane.SessionKeyV6, func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (d *protocolClearDP) DeleteSession(key dataplane.SessionKey) error {
	d.deleted = append(d.deleted, key)
	delete(d.sessions, key)
	return nil
}

func (d *protocolClearDP) DeleteSessionV6(dataplane.SessionKeyV6) error { return nil }
func (d *protocolClearDP) DeleteDNATEntry(dataplane.DNATKey) error      { return nil }
func (d *protocolClearDP) DeleteDNATEntryV6(dataplane.DNATKeyV6) error  { return nil }

func TestClearFilteredSessionsSCTPOnly_10486(t *testing.T) {
	sctp := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{10, 0, 0, 2},
		SrcPort:  1000,
		DstPort:  2000,
		Protocol: 132,
	}
	tcp := sctp
	tcp.SrcIP[3] = 3
	tcp.Protocol = 6
	dp := &protocolClearDP{
		Manager:  dataplane.New(),
		sessions: map[dataplane.SessionKey]dataplane.SessionValue{sctp: {}, tcp: {}},
	}
	c := newRecordingCLI(t, dp)
	if err := c.handleClearSecurity([]string{"flow", "session", "protocol", "sctp"}); err != nil {
		t.Fatalf("handleClearSecurity: %v", err)
	}
	if _, ok := dp.sessions[sctp]; ok {
		t.Fatal("SCTP session survived protocol=sctp clear")
	}
	if _, ok := dp.sessions[tcp]; !ok {
		t.Fatal("TCP session was cleared by protocol=sctp")
	}
	if len(dp.deleted) != 1 || dp.deleted[0] != sctp {
		t.Fatalf("deleted keys = %v, want only SCTP key %v", dp.deleted, sctp)
	}
}

func TestClearFilteredSessionsBoundedWorkingSet_4886(t *testing.T) {
	const (
		batch = 4
		n     = 20 // > batch → multi-chunk
	)
	origBatch := cliClearFilteredBatch
	origObs := cliClearBatchObserver
	t.Cleanup(func() {
		cliClearFilteredBatch = origBatch
		cliClearBatchObserver = origObs
	})
	cliClearFilteredBatch = batch

	var chunks int32
	var maxChunk int32
	cliClearBatchObserver = func(chunkLen int) {
		atomic.AddInt32(&chunks, 1)
		for {
			m := atomic.LoadInt32(&maxChunk)
			if int32(chunkLen) <= m || atomic.CompareAndSwapInt32(&maxChunk, m, int32(chunkLen)) {
				break
			}
		}
	}

	dp := &orderedClearDP{
		Manager: dataplane.New(),
		vals:    map[dataplane.SessionKey]dataplane.SessionValue{},
		deleted: map[dataplane.SessionKey]bool{},
	}
	for i := 0; i < n; i++ {
		// Non-NAT TCP sessions (no reverse/DNAT companion): only the forward
		// key is collected, so the chunk size == forward-key count.
		k := dataplane.SessionKey{Protocol: 6, SrcPort: uint16(1000 + i)}
		dp.keys = append(dp.keys, k)
		dp.vals[k] = dataplane.SessionValue{}
	}

	c := newRecordingCLI(t, dp)
	if err := c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"}); err != nil {
		t.Fatalf("handleClearSecurity: %v", err)
	}

	if got := atomic.LoadInt32(&chunks); got == 0 {
		t.Fatal("clear did not proceed in chunks (bounded-batch observer never fired) — snapshot-all path?")
	}
	if got := atomic.LoadInt32(&maxChunk); got > batch {
		t.Fatalf("peak collected chunk = %d, want <= batch %d (working set not bounded)", got, batch)
	}
	if got := atomic.LoadInt32(&chunks); got < n/batch {
		t.Fatalf("only %d chunk(s) for %d sessions at batch %d — want >= %d (not actually chunked)", got, n, batch, n/batch)
	}
	// Correctness: every matching session was cleared (exact set, no leak).
	if dp.nDelete != n {
		t.Fatalf("cleared %d sessions, want %d (bounded clear must clear the same set as snapshot-all)", dp.nDelete, n)
	}
}
