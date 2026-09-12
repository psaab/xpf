package userspace

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #9714 — the helper requests must carry PeerDelete exactly when the caller is
// the peer path. These run without CAP_BPF against the real session socket
// (newSyncOnlyManager9146), so they observe the wire, not a hook.

func TestAPeerBatchDeleteMarksEveryHelperRequest9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	const tenant = uint32(100007)
	_, _, _ = m.BatchDeletePeerSyncedSessionsScoped(scopedKeys9364(tenant, 1234, 1235))

	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("FIXTURE: recorded %d delete requests, want 2", len(got))
	}
	for i, req := range got {
		if !req.PeerDelete {
			t.Errorf("request %d is not marked PeerDelete; the helper cannot refuse a peer delete of a "+
				"live local session", i)
		}
		if req.RoutingDomain != tenant {
			t.Errorf("request %d lost its routing domain (%d)", i, req.RoutingDomain)
		}
	}
}

func TestAnOrdinaryBatchDeleteStaysUnmarked9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	_, _ = m.BatchDeleteSessionsScoped(scopedKeys9364(100007, 1234, 1235))

	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("FIXTURE: recorded %d delete requests, want 2", len(got))
	}
	for i, req := range got {
		if req.PeerDelete {
			t.Errorf("request %d of an ordinary delete (GC, clear) is marked PeerDelete; the helper would "+
				"refuse a delete it must perform", i)
		}
	}
}

func TestAMarkedSingleDeleteMarksBothHalves9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	k := key9146()
	rev := dataplane.SessionKey{SrcIP: k.DstIP, DstIP: k.SrcIP, SrcPort: k.DstPort, DstPort: k.SrcPort, Protocol: k.Protocol}
	val := dataplane.SessionValue{RoutingDomain: 100007, ReverseKey: rev}

	m.mu.Lock()
	m.syncDeleteV4LockedMarked(k, val, true, true)
	m.mu.Unlock()
	marked := rec.all()
	if len(marked) != 2 {
		t.Fatalf("FIXTURE: recorded %d requests for a marked delete, want 2 (key + reverse)", len(marked))
	}
	for i, req := range marked {
		if !req.PeerDelete {
			t.Errorf("half %d of a peer single-key delete is not marked", i)
		}
	}

	m.mu.Lock()
	m.syncDeleteV4Locked(k, val, true)
	m.mu.Unlock()
	all := rec.all()
	if len(all) != 4 {
		t.Fatalf("FIXTURE: recorded %d requests after the unmarked delete, want 4", len(all))
	}
	for i, req := range all[2:] {
		if req.PeerDelete {
			t.Errorf("half %d of an ordinary single-key delete is marked PeerDelete", i)
		}
	}
}

func TestAPeerV6BatchDeleteMarksEveryHelperRequest9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	scoped := []dataplane.ScopedSessionKeyV6{
		{Key: dataplane.SessionKeyV6{SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(443), Protocol: 6}, RoutingDomain: 100007},
	}
	_, _, _ = m.BatchDeletePeerSyncedSessionsScopedV6(scoped)

	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("FIXTURE: recorded %d delete requests, want 1", len(got))
	}
	if !got[0].PeerDelete {
		t.Errorf("the IPv6 peer batch delete is not marked PeerDelete")
	}
}

// #9714 review F1: the helper's in-band refusal reaches the caller by key, so the
// store can keep that flow's DNAT row and the Manager its mirror row.
func TestARefusedPeerBatchDeleteIsReportedByKey9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseFirst(peerDeleteRefusedLocalOwned)
	keys := scopedKeys9364(100007, 1234, 1235)

	_, refused, _ := m.BatchDeletePeerSyncedSessionsScoped(keys)

	if got := len(rec.all()); got != 2 {
		t.Fatalf("FIXTURE: recorded %d helper requests, want 2", got)
	}
	if len(refused) != 1 || refused[0] != keys[0] {
		t.Errorf("refused = %v, want exactly the first key: the store would delete the DNAT row of a flow "+
			"the helper kept, or keep one it removed (#9714)", refused)
	}
}

// #9714 review F1: a refused single-key peer delete does not go on to delete the
// reverse companion of the flow the helper kept.
func TestARefusedPeerSingleDeleteKeepsTheReverse9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseFirst(peerDeleteRefusedLocalOwned)
	k := key9146()
	rev := dataplane.SessionKey{SrcIP: k.DstIP, DstIP: k.SrcIP, SrcPort: k.DstPort, DstPort: k.SrcPort, Protocol: k.Protocol}

	m.mu.Lock()
	refused := m.syncDeleteV4LockedMarked(k, dataplane.SessionValue{RoutingDomain: 100007, ReverseKey: rev}, true, true)
	m.mu.Unlock()

	if !refused {
		t.Errorf("the helper refused the marked delete but the Manager did not report it (#9714)")
	}
	if got := len(rec.all()); got != 1 {
		t.Errorf("recorded %d helper requests, want 1: a refused forward must keep its reverse half", got)
	}
}

// #9714: an UNMARKED delete never reads an in-band answer as a peer refusal, even the
// same text, so an operator clear always goes on to the reverse half.
func TestAnUnmarkedDeleteNeverReadsAPeerRefusal9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseFirst(peerDeleteRefusedLocalOwned)
	k := key9146()
	rev := dataplane.SessionKey{SrcIP: k.DstIP, DstIP: k.SrcIP, SrcPort: k.DstPort, DstPort: k.SrcPort, Protocol: k.Protocol}

	m.mu.Lock()
	refused := m.syncDeleteV4LockedMarked(k, dataplane.SessionValue{RoutingDomain: 100007, ReverseKey: rev}, true, false)
	m.mu.Unlock()

	if refused {
		t.Errorf("an unmarked delete reported a peer refusal")
	}
	if got := len(rec.all()); got != 2 {
		t.Errorf("recorded %d helper requests, want 2: an unmarked delete must still send the reverse half", got)
	}
}

// #9714 review round 2, finding 1: ONLY a key the helper EXPLICITLY applied loses its
// BPF mirror row, and a row that is already gone neither counts as deleted nor stops
// the rest.
//
// This cell used to drive deleteUnrefusedMirrorRows, which deleted the COMPLEMENT of
// the refused set. That complement is strictly larger than "applied": it also holds
// keys whose transport failed and keys the batch never sent at all after an
// unreachable helper. At THIS layer those three are indistinguishable — each is
// simply absent from `applied` — so the cell asserts only what it can observe here,
// and the refused-versus-never-answered distinction is asserted upstream where it is
// observable, by TestAnAbortedBatchReportsTheUnsentTailAsNotAttempted9714.
func TestOnlyAnAppliedKeyLosesItsMirrorRow9714(t *testing.T) {
	keys := scopedKeys9364(100007, 1234, 1235, 1236)
	// The helper answered for two of the three. keys[0] is NOT applied — refused,
	// transport-failed, or never sent; this layer cannot tell them apart and does
	// not need to, because none of them licenses deleting the row.
	applied := []dataplane.ScopedSessionKey{keys[1], keys[2]}
	var attempted []dataplane.ScopedSessionKey
	deleted, err := deleteAppliedMirrorRows(applied, func(sk dataplane.ScopedSessionKey) error {
		attempted = append(attempted, sk)
		if sk == keys[1] {
			return ebpf.ErrKeyNotExist
		}
		return nil
	})
	if err != nil {
		t.Fatalf("a missing mirror row is not an error: %v", err)
	}
	if slices.Contains(attempted, keys[0]) {
		t.Errorf("a key the helper did not apply had its BPF mirror row deleted; bulk export would then drop " +
			"a flow the helper kept, and refresh cannot recreate it (BPF_EXIST) (#9714)")
	}
	if len(attempted) != 2 || deleted != 1 {
		t.Errorf("attempted %d rows and counted %d deleted, want 2 and 1: a missing row must neither count nor "+
			"stop the rest", len(attempted), deleted)
	}
}

// #9714 review round 2, finding 1 — the WIRING, not the pure function.
//
// TestOnlyAnAppliedKeyLosesItsMirrorRow9714 drives deleteAppliedMirrorRows with a
// LITERAL slice, so it cannot see whether anything still fills that slice. A
// mutation run proved the gap rather than guessing at it: deleting the `applied`
// collection arm from BOTH the V4 and V6 marked-delete twins broke no cell anywhere,
// while leaving the batch deleting zero mirror rows — a silent regression in the
// direction of doing nothing, which no existing assertion could see.
//
// The gap was introduced by the fix itself. Before the inversion the teardown was
// driven by `scoped` directly, so there was no collection step that could break.
// It asserts on the COLLECTION ARM directly rather than on a mirror-row count,
// deliberately. Seeding real rows needs injectSessionMaps, which builds real eBPF
// maps and SKIPS without CAP_BPF — and a cell that skips is not coverage, least of
// all in the environment where this gap was found. The arm is reachable without
// privileges through the session socket, so the cell measures the mutated code
// itself instead of a downstream consequence of it.
func TestAPeerBatchCollectsTheAppliedKeysByName9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseFirst(peerDeleteRefusedLocalOwned)
	keys := scopedKeys9364(100007, 1234, 1235, 1236)

	var refused, applied []dataplane.ScopedSessionKey
	if err := m.deleteHelperSessionsScopedV4Marked(keys, true, &refused, &applied); err != nil {
		t.Fatalf("marked scoped delete: %v", err)
	}

	if got := len(rec.all()); got != len(keys) {
		t.Fatalf("FIXTURE: the helper saw %d requests, want %d — a per-key refusal must not abort the batch "+
			"(#5881), or there is no applied tail for this cell to measure", got, len(keys))
	}
	if !slices.Equal(refused, keys[:1]) {
		t.Errorf("refused = %v, want exactly the first key: the helper refused it and it must be named", refused)
	}
	if !slices.Equal(applied, keys[1:]) {
		t.Errorf("applied = %v, want every key the helper answered WITHOUT refusing. The applied set is what "+
			"drives the mirror-row teardown, so a short or empty set silently tears down nothing, and a set "+
			"that wrongly includes the refused key tears down a live local session (#9714 r2 F1)", applied)
	}
}

// #9714 review round 2, finding 8: a refusal in a LATER chunk must be reported by
// ITS OWN key.
//
// Deletes reach the helper in chunks of sessionHelperDeleteChunk (256), and a refusal
// is recorded as keys[start+i]. The review names the mutant that survives everything
// else: keys[start+i] -> keys[start], which reports the chunk's FIRST key instead of
// the refused one. Every other cell refuses request 1 of chunk 1, where start+i and
// start are the SAME index, so none of them can see it — the fixture, not the
// assertion, is what was hiding the bug.
//
// The consequence is precise and bad in both directions at once: the refused session
// loses the mirror row it was supposed to keep, and an unrelated session keeps a row
// it was supposed to lose.
func TestARefusalInALaterChunkIsReportedByItsOwnKey9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	const n = sessionHelperDeleteChunk + 5 // spans two chunks
	ports := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		ports = append(ports, uint16(20000+i))
	}
	keys := scopedKeys9364(100007, ports...)
	// 1-based, and deliberately inside the SECOND chunk so that start != 0.
	const refusedNth = sessionHelperDeleteChunk + 2
	rec.refuseNth(refusedNth, peerDeleteRefusedLocalOwned)

	var refused, applied []dataplane.ScopedSessionKey
	if err := m.deleteHelperSessionsScopedV4Marked(keys, true, &refused, &applied); err != nil {
		t.Fatalf("marked scoped delete: %v", err)
	}

	if got := len(rec.all()); got != n {
		t.Fatalf("FIXTURE: the helper saw %d requests, want %d — the batch must span two chunks and "+
			"survive a per-key refusal (#5881), or there is no later chunk to measure", got, n)
	}
	want := keys[refusedNth-1]
	if len(refused) != 1 || refused[0] != want {
		t.Errorf("refused = %v, want exactly [%v]: a refusal recorded against the CHUNK'S FIRST key "+
			"instead of its own strands the refused session — its mirror row is deleted — and spares an "+
			"unrelated one (#9714 r2 F8)", refused, want)
	}
	if len(applied) != n-1 {
		t.Errorf("applied = %d keys, want %d: every key the helper answered without refusing", len(applied), n-1)
	}
	if slices.Contains(applied, want) {
		t.Errorf("the refused key %v was ALSO reported as applied, so its mirror row would be deleted "+
			"despite the helper keeping the session", want)
	}
}

// #9714 review round 2, finding 1: after a transport failure aborts the batch, every
// request the loop NEVER SENT must report errSessionSyncNotAttempted — not nil.
//
// nil is the helper's "I applied it", and it is the single fact that licenses a caller
// to delete a BPF mirror row. A chunk is up to sessionHelperDeleteChunk (256)
// requests, so an unreachable helper on the FIRST request used to manufacture up to
// 255 phantom successes, and the peer batch then deleted 255 mirror rows for sessions
// the helper still holds. Refresh cannot put them back: it writes with BPF_EXIST
// precisely so it will not recreate a deleted entry.
//
// Until this cell, sendSessionSyncBatchOutcomes had NO direct coverage at all, which
// is how a doc comment stating "a request after that one was never sent and reports
// nil" survived as if it were a contract rather than the defect.
//
// The abort itself is #5380 behaviour and is deliberately unchanged, so this cell
// pins the abort AND the marking together: marking the tail while losing the
// fast-fail would trade one defect for another, and the `sent` assertion is what
// keeps this cell from passing vacuously if the abort ever stops happening.
func TestAnAbortedBatchReportsTheUnsentTailAsNotAttempted9714(t *testing.T) {
	reqs := make([]SessionSyncRequest, 4)
	for i := range reqs {
		reqs[i].Operation = "delete"
	}
	sent := 0
	outcomes := sendSessionSyncBatchOutcomes(reqs, func(ControlRequest) error {
		sent++
		if sent == 2 {
			return fmt.Errorf("write: %w", errSessionHelperUnreachable)
		}
		return nil
	})

	if sent != 2 {
		t.Fatalf("FIXTURE: the batch sent %d requests, want 2 — it must abort ON the transport failure "+
			"(#5380), or there is no unsent tail for this cell to measure", sent)
	}
	if len(outcomes) != len(reqs) {
		t.Fatalf("FIXTURE: %d outcomes for %d requests", len(outcomes), len(reqs))
	}
	if outcomes[0] != nil {
		t.Errorf("request 0 was sent and applied, but reports %v", outcomes[0])
	}
	if !errors.Is(outcomes[1], errSessionHelperUnreachable) {
		t.Errorf("request 1 failed at the transport, but reports %v", outcomes[1])
	}
	for i := 2; i < len(reqs); i++ {
		if !errors.Is(outcomes[i], errSessionSyncNotAttempted) {
			t.Errorf("request %d was NEVER SENT but reports %v; a nil there reads as \"the helper applied it\" "+
				"and licenses deleting the mirror row of a session the helper still holds (#9714 r2 F1)",
				i, outcomes[i])
		}
	}
}

// #9714: only the peer-delete refusal token is a kept flow. Another in-band refusal of
// a marked delete (an ambiguous routing domain) must not be reported as one.
func TestAnAmbiguousRefusalIsNotAPeerRefusal9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseFirst("synced-delete-refused:ambiguous-routing-domain (5-tuple matches 2 routing instances)")

	_, refused, _ := m.BatchDeletePeerSyncedSessionsScoped(scopedKeys9364(100007, 1234))

	if len(refused) != 0 {
		t.Errorf("an ambiguous-routing-domain refusal was read as a peer refusal: %v", refused)
	}
}

// #9714 review F3: the single-key peer delete asks the helper even when the BPF mirror
// holds no row for the key, which is exactly when the store falls back to it.
func TestAPeerSingleDeleteAsksTheHelperWithoutAMirrorRow9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)

	_, _ = m.DeletePeerSyncedSession(key9146())

	got := rec.all()
	if len(got) != 1 || !got[0].PeerDelete {
		t.Errorf("recorded %d helper requests (%v): the helper must be asked, marked, even though the mirror "+
			"holds nothing for the key (#9714)", len(got), got)
	}
}
