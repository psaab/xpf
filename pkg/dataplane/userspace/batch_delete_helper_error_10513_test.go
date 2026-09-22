package userspace

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"golang.org/x/sys/unix"
)

// #10513: BatchDeleteSessionsScoped deleted the BPF mirror FIRST, then discarded
// the helper result (`_ = m.deleteHelperSessionsScopedV4/V6`). Mirror-success +
// helper-failure returned nil through DeleteBatchKnownV4/V6 ->
// deleteInvalidatedSessions, so the daemon logged commit-clear success and
// applyAndSyncCommitted saw joined==nil and marked the config converged — with
// authoritative helper rows still installed. The #5578 contract (matched
// sessions stay installed, errors surface) requires the error to surface.
//
// THESE CELLS RUN WITHOUT CAP_BPF, deliberately (see the #9364 file header: a
// skipping cell scores every mutation as SURVIVED). newSyncOnlyManager9146
// touches no map; the unloaded bpfShim reports ErrDataplaneNotArmed for the
// mirror half, so every cell asserts on the HELPER leg of the returned error,
// not on mere non-nil — pre-fix the helper leg is absent and each fault arm
// goes RED.
//
// Arm 1 (transport failure + unsent tail): the helper is unreachable, so the
// first request transport-fails and the rest of the chunk is never sent
// (errSessionSyncNotAttempted tail, #9714 r2 F1). The batch must surface
// errSessionHelperUnreachable, not clean success.
func TestBatchDeleteSessionsScopedSurfacesHelperTransportError10513(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.ln.Close() // dial fails: first request transport-fails, tail never sent

	_, err := m.BatchDeleteSessionsScoped(scopedKeys9364(100007, 1234, 1235, 1236))
	if !errors.Is(err, errSessionHelperUnreachable) {
		t.Fatalf("BatchDeleteSessionsScoped with an unreachable helper = %v, want "+
			"errSessionHelperUnreachable — a clean return reports commit-clear success "+
			"while authoritative helper rows remain (#10513)", err)
	}
}

// Arm 2 (semantic refusal): the helper is alive but refuses the delete
// (unrecognized/ambiguous routing domain, #8636). A refusal answers the
// request with resp.OK=false; it must surface, not read as success.
func TestBatchDeleteSessionsScopedSurfacesHelperRefusal10513(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseFirst("synced-delete-refused:ambiguous-routing-domain (5-tuple matches 2 routing instances)")

	_, err := m.BatchDeleteSessionsScoped(scopedKeys9364(100007, 1234))
	if err == nil || !strings.Contains(err.Error(), "synced-delete-refused:ambiguous-routing-domain") {
		t.Fatalf("BatchDeleteSessionsScoped with a refused helper delete = %v, want the "+
			"ambiguous-routing-domain refusal to surface — swallowing it reports success "+
			"while the helper keeps the session (#10513)", err)
	}
}

func scopedKeys10513V6(domain uint32, ports ...uint16) []dataplane.ScopedSessionKeyV6 {
	out := make([]dataplane.ScopedSessionKeyV6, 0, len(ports))
	for _, p := range ports {
		out = append(out, dataplane.ScopedSessionKeyV6{
			Key: dataplane.SessionKeyV6{
				SrcPort: hostToNetwork16(p), DstPort: hostToNetwork16(443), Protocol: 6,
			},
			RoutingDomain: domain,
		})
	}
	return out
}

// V6 twin of arm 1. Not symmetry for its own sake: V6 has its own scoped
// delete function, and the discard lived in both.
func TestBatchDeleteSessionsScopedV6SurfacesHelperTransportError10513(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.ln.Close()

	_, err := m.BatchDeleteSessionsScopedV6(scopedKeys10513V6(100008, 1234, 1235, 1236))
	if !errors.Is(err, errSessionHelperUnreachable) {
		t.Fatalf("BatchDeleteSessionsScopedV6 with an unreachable helper = %v, want "+
			"errSessionHelperUnreachable (#10513)", err)
	}
}

// V6 twin of arm 2.
func TestBatchDeleteSessionsScopedV6SurfacesHelperRefusal10513(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseFirst("synced-delete-refused:ambiguous-routing-domain (5-tuple matches 2 routing instances)")

	_, err := m.BatchDeleteSessionsScopedV6(scopedKeys10513V6(100008, 1234))
	if err == nil || !strings.Contains(err.Error(), "synced-delete-refused:ambiguous-routing-domain") {
		t.Fatalf("BatchDeleteSessionsScopedV6 with a refused helper delete = %v, want the "+
			"ambiguous-routing-domain refusal to surface (#10513)", err)
	}
}

// The direct Manager tests above prove the helper leg is returned, but the
// production store has another hazard: batchDeleteV4/V6 treats unix.ENOENT as
// a mirror not-found, retries per key, and ignores those retry errors. A
// missing helper socket must therefore be tested through DeleteBatchKnown*;
// the surfaced wrapper must preserve errSessionHelperUnreachable without
// exposing ENOENT to errors.Is.
func TestDeleteBatchKnownV4DoesNotSwallowMissingHelper10513(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.ln.Close()
	store := dataplane.NewDataPlaneSessionStore(NewLegacyDataPlaneAdapter(m))

	_, err := store.DeleteBatchKnownV4([]dataplane.SessionEntryV4{{
		Key:   key9146(),
		Value: dataplane.SessionValue{RoutingDomain: 100007},
	}}, dataplane.DeleteReasonGCExpired, false)
	if !errors.Is(err, errSessionHelperUnreachable) {
		t.Fatalf("DeleteBatchKnownV4 with a missing helper socket = %v, want "+
			"errSessionHelperUnreachable; the batch must not retry and swallow the "+
			"authoritative helper failure (#10513)", err)
	}
	if errors.Is(err, unix.ENOENT) {
		t.Fatalf("DeleteBatchKnownV4 exposed unix.ENOENT in its error chain: %v; "+
			"batchDeleteV4 classifies ENOENT as mirror NotFound and would discard "+
			"the helper failure on its per-key retry (#10513)", err)
	}
}

func TestDeleteBatchKnownV6DoesNotSwallowMissingHelper10513(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.ln.Close()
	store := dataplane.NewDataPlaneSessionStore(NewLegacyDataPlaneAdapter(m))
	key := dataplane.SessionKeyV6{
		SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(443), Protocol: 6,
	}

	_, err := store.DeleteBatchKnownV6([]dataplane.SessionEntryV6{{
		Key:   key,
		Value: dataplane.SessionValueV6{RoutingDomain: 100008},
	}}, dataplane.DeleteReasonGCExpired, false)
	if !errors.Is(err, errSessionHelperUnreachable) {
		t.Fatalf("DeleteBatchKnownV6 with a missing helper socket = %v, want "+
			"errSessionHelperUnreachable (#10513)", err)
	}
	if errors.Is(err, unix.ENOENT) {
		t.Fatalf("DeleteBatchKnownV6 exposed unix.ENOENT in its error chain: %v; "+
			"batchDeleteV6 would classify it as mirror NotFound and swallow the "+
			"helper failure on retry (#10513)", err)
	}
}

// LOAD-BEARING CONTROL — the deletes that must still SUCCEED.
//
// Propagating helper errors must not invent them: with a healthy helper the
// batch carries no helper leg (the unloaded-shim mirror error is the harness
// talking, not the fix), and every delete still reaches the helper wire.
func TestBatchDeleteSessionsScopedHealthyHelperAddsNoError10513(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)

	_, err := m.BatchDeleteSessionsScoped(scopedKeys9364(100007, 1234, 1235))
	if errors.Is(err, errSessionHelperUnreachable) || (err != nil && strings.Contains(err.Error(), "userspace helper")) {
		t.Fatalf("a healthy helper must contribute no error leg, got %v", err)
	}
	if got := rec.all(); len(got) != 2 {
		t.Fatalf("FIXTURE FAILED: recorded %d delete requests, want 2 — the control cannot "+
			"prove deletes still flow if the requests never reached the socket", len(got))
	}

	m6, rec6 := newSyncOnlyManager9146(t)
	_, err = m6.BatchDeleteSessionsScopedV6(scopedKeys10513V6(100008, 1234, 1235))
	if errors.Is(err, errSessionHelperUnreachable) || (err != nil && strings.Contains(err.Error(), "userspace helper")) {
		t.Fatalf("a healthy helper must contribute no V6 error leg, got %v", err)
	}
	if got := rec6.all(); len(got) != 2 {
		t.Fatalf("FIXTURE FAILED: recorded %d V6 delete requests, want 2", len(got))
	}
}
