package userspace

import (
	"encoding/hex"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #15955 regression suite: the publish-path hash dedup must be invisible.
//
// Before the fix every PreparedLocked publish hashed the snapshot up to
// three times (dedup compare on `next`, digest stamp at the send site,
// post-publish lastSnapshotHash). The deduped publishers now hash the
// final publish snapshot ONCE and thread that hash into the send site.
// These tests pin, per publisher:
//
//   - exactly 1 snapshotContentHash call per publish in the common
//     (ClearPolicies-unset) case — the pre-send hash is reused for the
//     stamp and for lastSnapshotHash — and 1 call on a dedup skip (no
//     send); the authorized-clear path is the only one that pays a
//     second, spent-marker recompute;
//   - the ContentDigest on the wire equals the pre-fix stamped digest
//     over the exact sent struct, and the recorded lastSnapshotHash
//     equals the value the pre-fix post-send hash produced (the spent-
//     marker hash on the clear path — see postPublishHash);
//   - ClearPolicies (NOT hash-zeroed) is handled explicitly: the
//     stamped digest describes the pre-send (marker-in-force) content,
//     while the recorded lastSnapshotHash equals the pre-fix post-send
//     (spent-marker) value, so the next ordinary stripped partial
//     dedups exactly as before and the helper never sees a spent
//     marker replayed;
//   - requestApplySnapshotLocked publishers (scheduler, worker-arm) are
//     NOT deduped: prepareSnapshotForApply may rebuild sections after
//     any earlier hash, so their post-publish hash stays authoritative
//     and recomputed.

func hashCount15955() uint64 { return snapshotContentHashCalls.Load() }

func resetHashCount15955() { snapshotContentHashCalls.Store(0) }

// overlayManager15955 builds a Manager whose next overlay publish will
// actually send (content differs from the retained snapshot).
func overlayManager15955(t *testing.T, sent *[]ConfigSnapshot) (*Manager, *config.Config) {
	t.Helper()
	cfg := overlayTestConfig()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.generation = 7
	m.lastSnapshot = mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	if h, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = h
	} else {
		t.Fatal("fixture snapshot did not hash")
	}
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" && req.Snapshot != nil {
			*sent = append(*sent, *req.Snapshot)
			if status != nil {
				*status = ProcessStatus{
					ConfigSnapshotProtocolVersion: ProtocolVersion,
					LastSnapshotGeneration:        req.Snapshot.Generation,
					LastFIBGeneration:             req.Snapshot.FIBGeneration,
				}
			}
		}
		return nil
	}
	return m, cfg
}

func TestPublishHashDedupOverlayCountsOnce15955(t *testing.T) {
	var sent []ConfigSnapshot
	m, cfg := overlayManager15955(t, &sent)

	resetHashCount15955()
	published, err := m.PublishRouteOverlaySnapshot(cfg, []config.RouteOverlayEntry{
		{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"},
	}, nil)
	if err != nil || !published {
		t.Fatalf("overlay publish = (%t, %v), want a publish", published, err)
	}
	if len(sent) != 1 {
		t.Fatalf("sent %d apply_snapshot requests, want 1", len(sent))
	}
	if got := hashCount15955(); got != 1 {
		t.Fatalf("overlay publish hashed %d times, want 1 (the pre-send publish hash is reused for the stamp and, ClearPolicies being unset here, for lastSnapshotHash); pre-fix was 3", got)
	}
	// The recorded hash must equal the pre-fix post-send value: the
	// hash of the sent struct (whose ClearPolicies is unset on this
	// path, so it equals the prehash the publisher computed).
	want, ok := snapshotContentHash(&sent[0])
	if !ok {
		t.Fatal("sent snapshot did not hash")
	}
	if m.lastSnapshotHash != want {
		t.Fatalf("lastSnapshotHash = %x, want hash of sent content %x", m.lastSnapshotHash, want)
	}

	// A duplicate publish of the same content must dedup-skip with a
	// single hash and no second send.
	resetHashCount15955()
	published, err = m.PublishRouteOverlaySnapshot(cfg, []config.RouteOverlayEntry{
		{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"},
	}, nil)
	if err != nil || published {
		t.Fatalf("duplicate overlay publish = (%t, %v), want a dedup skip", published, err)
	}
	if got := hashCount15955(); got != 1 {
		t.Fatalf("dedup skip hashed %d times, want 1", got)
	}
	if len(sent) != 1 {
		t.Fatalf("dedup skip sent a second snapshot (%d total)", len(sent))
	}
}

// TestPublishHashDedupClearPoliciesHash15955 pins the ClearPolicies
// subtlety: the marker rides the send, is spent by the send site, and is
// NOT zeroed inside snapshotContentHash. If the post-publish bookkeeping
// hashed the spent struct, lastSnapshotHash would describe content the
// helper never held and every following dedup compare would miss.
func TestPublishHashDedupClearPoliciesHash15955(t *testing.T) {
	var sent []ConfigSnapshot
	m := New()
	m.controlRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.Type == "apply_snapshot" && req.Snapshot != nil {
			sent = append(sent, *req.Snapshot)
		}
		return nil
	}
	snap := ConfigSnapshot{Version: ProtocolVersion, Generation: 7, FIBGeneration: 3,
		GeneratedAt: time.Unix(100, 0).UTC(), DefaultPolicy: "permit"}
	snap.ClearPolicies = true // an authorized clear, as Manager.Compile marks

	// The caller's prehash is computed BEFORE the reset so the counter
	// measures only what the send site itself hashes: with the dedup it
	// must be zero (the stamp reuses the supplied hash); pre-fix the
	// send site's stampSnapshotContentDigest would have added one.
	pre := mustHash15955(t, &snap)
	resetHashCount15955()
	m.mu.Lock()
	err := m.requestApplySnapshotPrehashedLocked(&snap, nil, pre, true)
	m.mu.Unlock()
	// Capture the send-site hash count immediately: every hash below this
	// line is this test's own recompute, not the send's.
	sendSiteHashes := hashCount15955()
	if err != nil {
		t.Fatalf("prehashed send: %v", err)
	}
	if len(sent) != 1 || !sent[0].ClearPolicies {
		t.Fatalf("sent = %+v, want one snapshot WITH the clear marker", sent)
	}
	if snap.ClearPolicies {
		t.Fatal("marker must be SPENT after the send (retained clones must not inherit it)")
	}
	// The stamped digest describes the marker-in-force content.
	preHash, ok := snapshotContentHashWithClear(&sent[0], true)
	if !ok {
		t.Fatal("sent snapshot did not hash")
	}
	if got, want := sent[0].ContentDigest, hex.EncodeToString(preHash[:]); got != want {
		t.Fatalf("wire digest %q, want pre-send (marker-in-force) digest %q", got, want)
	}
	// And it must differ from the spent-marker hash — the two are
	// distinguishable precisely because ClearPolicies is not hash-zeroed.
	// sent[0] is the hook's copy of the wire struct, which still carries
	// the marker; the spent form is the same content with it cleared.
	spentHash, ok := snapshotContentHashWithClear(&sent[0], false)
	if !ok {
		t.Fatal("sent snapshot did not hash")
	}
	if spentHash == preHash {
		t.Fatal("pre-send and spent-marker hashes must differ: ClearPolicies is helper-visible content")
	}
	if sendSiteHashes != 0 {
		t.Fatalf("prehashed send site hashed %d times, want 0 (the stamp must reuse the supplied hash, not recompute)", sendSiteHashes)
	}
}

func mustHash15955(t *testing.T, snap *ConfigSnapshot) [32]byte {
	t.Helper()
	h, ok := snapshotContentHash(snap)
	if !ok {
		t.Fatal("snapshot did not hash")
	}
	return h
}

// TestPublishHashDedupSchedulerRebuildStillAuthoritative15955 proves the
// requestApplySnapshotLocked path was NOT deduped: UpdatePolicyScheduleState
// sends through requestApplySnapshotLocked, whose prepareSnapshotForApply
// step runs after any conceivable prehash. Its post-publish hash must
// still be recomputed over the prepared publishSnap (the sections the
// helper actually received), and the publish must still converge.
func TestPublishHashDedupSchedulerRebuildStillAuthoritative15955(t *testing.T) {
	cfg := schedCfg10005()
	controlSock := shortSockDir10005(t)
	m := New()
	seedOpenBaseline10005(t, m, cfg, controlSock, 7)
	m.mu.Lock()
	m.publishedSnapshot = 7
	if h, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = h
	}
	m.mu.Unlock()
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" && req.Snapshot != nil && status != nil {
			*status = ProcessStatus{
				ConfigSnapshotProtocolVersion: ProtocolVersion,
				LastSnapshotGeneration:        req.Snapshot.Generation,
				LastFIBGeneration:             req.Snapshot.FIBGeneration,
			}
		}
		return nil
	}

	resetHashCount15955()
	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false}); err != nil {
		t.Fatalf("scheduler publish: %v", err)
	}
	if m.lastSnapshot == nil {
		t.Fatal("scheduler publish retained no snapshot")
	}
	// The scheduler path retains the prepared sections by copying them
	// back from publishSnap into next (Neighbors deliberately excepted:
	// it keeps the retained, unfiltered set, and snapshotContentHash
	// filters internally), so a recomputed hash of the retained
	// snapshot must equal the recorded one.
	want, ok := snapshotContentHash(m.lastSnapshot)
	if !ok {
		t.Fatal("retained snapshot did not hash")
	}
	if m.lastSnapshotHash != want {
		t.Fatalf("scheduler lastSnapshotHash = %x, want recomputed hash of the prepared publish %x", m.lastSnapshotHash, want)
	}
	if got := hashCount15955(); got < 2 {
		t.Fatalf("scheduler publish hashed only %d times; the prepare-path post hash must still be computed (no dedup on requestApplySnapshotLocked paths)", got)
	}
}
