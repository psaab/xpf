package userspace

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
	"golang.org/x/sys/unix"
)

func removeSessionSocket10513(t *testing.T, rec *syncRec9146) {
	t.Helper()
	socketPath := rec.ln.Addr().String()
	if err := rec.ln.Close(); err != nil {
		t.Fatalf("close helper listener: %v", err)
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove helper socket %q: %v", socketPath, err)
	}
}

// scopedResultDP10513 embeds the published interface so the production session
// store can be driven without CAP_BPF. Its scoped methods return the
// helper-only result that Manager.BatchDeleteSessionsScoped[V6] must produce
// after a mirror ErrKeyNotExist plus helper failure; the retry counters prove
// batchDeleteV4/V6 do not misclassify that result as mirror NotFound.
type scopedResultDP10513 struct {
	dataplane.DataPlane
	v4Err, v6Err         error
	retriesV4, retriesV6 int
}

func (d *scopedResultDP10513) BatchDeleteSessionsScoped([]dataplane.ScopedSessionKey) (int, error) {
	return 0, d.v4Err
}
func (d *scopedResultDP10513) BatchDeleteSessionsScopedV6([]dataplane.ScopedSessionKeyV6) (int, error) {
	return 0, d.v6Err
}

func (d *scopedResultDP10513) DeleteSession(dataplane.SessionKey) error {
	d.retriesV4++
	return nil
}

func (d *scopedResultDP10513) DeleteSessionV6(dataplane.SessionKeyV6) error {
	d.retriesV6++
	return nil
}

// singularRecoveryDP10528 forces a mirror NotFound from the batch leg and
// delegates the recovery retry to the real singular Manager.DeleteSession.
// Closing the helper socket between those legs reproduces the narrow
// helper-dies-during-recovery race (#10528).
type singularRecoveryDP10528 struct {
	dataplane.DataPlane
	manager *Manager
	retries int
}

func (d *singularRecoveryDP10528) BatchDeleteSessions([]dataplane.SessionKey) (int, error) {
	return 0, ebpf.ErrKeyNotExist
}

func (d *singularRecoveryDP10528) DeleteSession(dataplane.SessionKey) error {
	d.retries++
	return d.manager.DeleteSession(key9146())
}

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

// Arm 2 (semantic refusal): the helper is alive but returns the requested
// unrecognized-domain token. Current Rust DELETE handling proceeds for an
// unrecognized wire domain; the recorder injects this stable non-OK response
// to pin Go's refusal propagation against that base behavior drift.
func TestBatchDeleteSessionsScopedSurfacesHelperUnrecognizedDomainRefusal10513(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseFirst("synced-import-refused:routing-domain-unrecognized")

	_, err := m.BatchDeleteSessionsScoped(scopedKeys9364(100007, 1234))
	if err == nil || !strings.Contains(err.Error(), "routing-domain-unrecognized") {
		t.Fatalf("BatchDeleteSessionsScoped with an unrecognized-domain refusal = %v, "+
			"want the refusal to surface — swallowing it reports success while the "+
			"helper keeps the session (#10513)", err)
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

// surfaceScopedHelperDeleteError is pure and shared by the V4/V6 callers. Pin
// its transport wrapper with a real ENOENT cause: the stable helper sentinel
// must remain discoverable, while the session-store NotFound classifier must
// not see the underlying dial cause.
func TestSurfaceScopedHelperDeleteErrorStripsENOENT10513(t *testing.T) {
	for _, family := range []string{"v4", "v6"} {
		raw := fmt.Errorf("%w: dial session socket: %w",
			errSessionHelperUnreachable, unix.ENOENT)
		got := surfaceScopedHelperDeleteError(family, raw)
		if !errors.Is(got, errSessionHelperUnreachable) {
			t.Errorf("%s wrapper = %v, lost errSessionHelperUnreachable", family, got)
		}
		if errors.Is(got, unix.ENOENT) {
			t.Errorf("%s wrapper = %v, exposes unix.ENOENT to the mirror retry classifier", family, got)
		}
	}
}

// The Manager's armed-mirror precedence branch returns the helper-only result
// when BPF reports key-not-found. Feed that result through the production store
// with an embedded-interface fake: a retry means the store has mistaken the
// helper failure for mirror NotFound, and the authoritative error is lost.
func TestScopedStoreDoesNotRetryHelperOnlyResult10513(t *testing.T) {
	dp := &scopedResultDP10513{
		v4Err: surfaceScopedHelperDeleteError("v4",
			fmt.Errorf("%w: dial session socket: %w", errSessionHelperUnreachable, unix.ENOENT)),
		v6Err: surfaceScopedHelperDeleteError("v6",
			fmt.Errorf("%w: dial session socket: %w", errSessionHelperUnreachable, unix.ENOENT)),
	}
	store := dataplane.NewDataPlaneSessionStore(dp)

	_, err := store.DeleteBatchKnownV4([]dataplane.SessionEntryV4{{
		Key: key9146(),
	}}, dataplane.DeleteReasonGCExpired, false)
	if err != dp.v4Err {
		t.Fatalf("V4 result = %v, want exact helper-only result %v", err, dp.v4Err)
	}
	if dp.retriesV4 != 0 {
		t.Fatalf("V4 retry count = %d, want 0; helper failure was classified as mirror NotFound", dp.retriesV4)
	}

	key := dataplane.SessionKeyV6{
		SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(443), Protocol: 6,
	}
	_, err = store.DeleteBatchKnownV6([]dataplane.SessionEntryV6{{
		Key: key,
	}}, dataplane.DeleteReasonGCExpired, false)
	if err != dp.v6Err {
		t.Fatalf("V6 result = %v, want exact helper-only result %v", err, dp.v6Err)
	}
	if dp.retriesV6 != 0 {
		t.Fatalf("V6 retry count = %d, want 0; helper failure was classified as mirror NotFound", dp.retriesV6)
	}
}

// The direct Manager tests above prove the helper leg is returned, but the
// production store has another hazard: after a mirror NotFound it retries
// remaining keys per key, surfacing non-NotFound errors and ignoring only
// sessionNotFound. A missing helper socket must therefore be tested through
// DeleteBatchKnown*; the surfaced wrapper must preserve errSessionHelperUnreachable
// without exposing ENOENT to errors.Is.
func TestDeleteBatchKnownV4DoesNotSwallowMissingHelper10513(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	removeSessionSocket10513(t, rec)
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

// TestDeleteBatchKnownV4SurfacesHelperENOENTDuringRecovery10528 pins the
// helper-dies-between-batch-and-retry precedence boundary. The singular
// Manager wrapper must hide raw ENOENT while retaining the helper sentinel, so
// batchDeleteV4 cannot misclassify the transport failure as mirror NotFound.
func TestDeleteBatchKnownV4SurfacesHelperENOENTDuringRecovery10528(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	removeSessionSocket10513(t, rec)
	dp := &singularRecoveryDP10528{manager: m}
	store := dataplane.NewDataPlaneSessionStore(dp)

	_, err := store.DeleteBatchKnownV4([]dataplane.SessionEntryV4{{
		Key: key9146(),
	}}, dataplane.DeleteReasonGCExpired, true)
	if !errors.Is(err, errSessionHelperUnreachable) {
		t.Fatalf("DeleteBatchKnownV4 recovery error = %v, want errSessionHelperUnreachable", err)
	}
	if errors.Is(err, unix.ENOENT) {
		t.Fatalf("DeleteBatchKnownV4 recovery error exposed unix.ENOENT: %v", err)
	}
	if dp.retries != 1 {
		t.Fatalf("singular recovery retries = %d, want 1", dp.retries)
	}
}

func TestDeleteBatchKnownV6DoesNotSwallowMissingHelper10513(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	removeSessionSocket10513(t, rec)
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
