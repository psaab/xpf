package daemon

// policy_inval_debt_12073_test.go — #12073 (W08-02): the commit-time session
// invalidation must not run against the still-live OLD policy when the
// dataplane publish fails or is deferred, and the retry/deferred publish that
// actually lands the new policy must run it exactly once.
//
// Defect shape: applyAndSyncCommitted (and the sync + rollback siblings) arm
// the #6948 plan, run the apply, and then clear whenever the apply error is
// not abort-class — even when the publish never happened (#5679 ordinary
// failure leaves the OLD snapshot live; XSK-startup success defers it via
// SnapshotPublishDeferred). The capture is consumed by that early clear, so
// the later retry/deferred landing runs NO invalidation at all: sessions the
// new policy should DENY keep forwarding, and sessions cleared early were
// dropped under a policy that was still live.
//
// Fix contract: the (old,new) pair is invalidation debt, persisted until the
// FIRST successful publish, then cleared exactly once — including the HA
// delete-sync. These cells drive the REAL applyAndSyncCommitted +
// applyConfigLocked body (no applyBodyForTest seam) with a fake dataplane
// whose ApplyConfig fails or defers on the first attempt and lands on retry.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vrrp"
)

// invalDebtTestDP12073 is a fake RuntimeDataPlane combining the session-store
// half of policyInvalTestDP (so clears are observable) with the scripted
// ApplyConfig half of runtimeOnlyApplyTestDP (so publish failure/deferral is
// injectable per attempt). Each ApplyConfig call consumes the next scripted
// outcome; LastApplyResult advances only on landed publishes, mirroring
// recordApplyResultLocked (called on success paths only).
type invalDebtTestDP12073 struct {
	dataplane.DataPlane // embedded nil — only the overridden methods are called

	applyCalls int
	// script[i] drives the i-th ApplyConfig call: err fails the publish
	// (#5679: OLD snapshot stays live), deferred marks a success that did
	// NOT publish (XSK startup). An empty script (or an exhausted one)
	// lands every publish.
	script []invalDebtOutcome12073

	gen       uint64
	lastApply *dataplane.ApplyResult

	// A landed snapshot re-stamps deleted-policy rows to the default sentinel,
	// so a post-publish scan cannot accidentally pass as a pre-publish capture.
	relabelPolicyID uint32

	v4        map[dataplane.SessionKey]dataplane.SessionValue
	v6        map[dataplane.SessionKeyV6]dataplane.SessionValueV6
	deletedV4 []dataplane.SessionKey
	deletedV6 []dataplane.SessionKeyV6
}

type invalDebtOutcome12073 struct {
	err      error
	deferred bool
}

func (d *invalDebtTestDP12073) Start(context.Context) error { return nil }
func (d *invalDebtTestDP12073) Close() error                { return nil }
func (d *invalDebtTestDP12073) Teardown() error             { return nil }

func (d *invalDebtTestDP12073) ApplyConfig(ctx context.Context, _ *config.Config) (*dataplane.ApplyResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	var outcome invalDebtOutcome12073
	if d.applyCalls < len(d.script) {
		outcome = d.script[d.applyCalls]
	}
	d.applyCalls++
	if outcome.err != nil {
		// #5679: a failed ApplyConfig records nothing — the last apply
		// result still describes the previous-good snapshot.
		return nil, outcome.err
	}
	out := &dataplane.ApplyResult{
		ZoneIDs:                 map[string]uint16{},
		SnapshotPublishDeferred: outcome.deferred,
	}
	d.gen++
	out.Generation = d.gen
	d.lastApply = out.Clone()
	if !outcome.deferred {
		d.relabelDeletedPolicySessions()
	}
	return out.Clone(), nil
}

func (d *invalDebtTestDP12073) relabelDeletedPolicySessions() {
	for key, value := range d.v4 {
		if value.PolicyID == d.relabelPolicyID {
			value.PolicyID = dataplane.DefaultPolicySentinelID
			d.v4[key] = value
		}
	}
	for key, value := range d.v6 {
		if value.PolicyID == d.relabelPolicyID {
			value.PolicyID = dataplane.DefaultPolicySentinelID
			d.v6[key] = value
		}
	}
}

func (d *invalDebtTestDP12073) LastApplyResult() *dataplane.ApplyResult {
	if d.lastApply != nil {
		return d.lastApply.Clone()
	}
	return &dataplane.ApplyResult{ZoneIDs: map[string]uint16{}}
}

func (d *invalDebtTestDP12073) Link() dataplane.LinkController { return noopLinkController{} }
func (d *invalDebtTestDP12073) HA() dataplane.HAController {
	return dataplane.NewDataPlaneHAController(nil)
}
func (d *invalDebtTestDP12073) Sessions() dataplane.SessionStore {
	return dataplane.NewDataPlaneSessionStore(d)
}
func (d *invalDebtTestDP12073) Telemetry() dataplane.Telemetry { return dataplane.TelemetryOf(nil) }
func (d *invalDebtTestDP12073) SessionDeltas() dpruntime.SessionDeltaSource {
	return nil
}

func (d *invalDebtTestDP12073) BatchIterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for k, v := range d.v4 {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (d *invalDebtTestDP12073) BatchIterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for k, v := range d.v6 {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (d *invalDebtTestDP12073) GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error) {
	value, ok := d.v4[key]
	if !ok {
		return dataplane.SessionValue{}, ebpf.ErrKeyNotExist
	}
	return value, nil
}

func (d *invalDebtTestDP12073) GetSessionV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	value, ok := d.v6[key]
	if !ok {
		return dataplane.SessionValueV6{}, ebpf.ErrKeyNotExist
	}
	return value, nil
}

func (d *invalDebtTestDP12073) BatchDeleteSessions(keys []dataplane.SessionKey) (int, error) {
	n := 0
	for _, k := range keys {
		d.deletedV4 = append(d.deletedV4, k)
		if _, ok := d.v4[k]; ok {
			delete(d.v4, k)
			n++
		}
	}
	return n, nil
}

func (d *invalDebtTestDP12073) BatchDeleteSessionsV6(keys []dataplane.SessionKeyV6) (int, error) {
	n := 0
	for _, k := range keys {
		d.deletedV6 = append(d.deletedV6, k)
		if _, ok := d.v6[k]; ok {
			delete(d.v6, k)
			n++
		}
	}
	return n, nil
}

func (d *invalDebtTestDP12073) DeleteDNATEntry(dataplane.DNATKey) error     { return nil }
func (d *invalDebtTestDP12073) DeleteDNATEntryV6(dataplane.DNATKeyV6) error { return nil }

// invalDebtHarness12073 wires a Daemon that drives the REAL commit path
// (applyAndSyncCommitted -> applyConfigLockedForCommit -> applyConfigLocked)
// with a scripted dataplane, a primary-for-RG cluster, and a connected HA
// session-sync pair so both the local deletes and the delete-sync are
// observable. oldCfg deletes p-web in newCfg; the session tables each hold
// one session admitted by p-web.
type invalDebtHarness12073 struct {
	d         *Daemon
	dp        *invalDebtTestDP12073
	sender    *cluster.SessionSync
	receiver  *cluster.SessionSync
	recvDP    *policyInvalTestDP
	oldCfg    *config.Config
	newCfg    *config.Config
	webSess   dataplane.SessionKey
	webSessV6 dataplane.SessionKeyV6
	webID     uint32
}

func newInvalDebtHarness12073(t *testing.T, script []invalDebtOutcome12073) *invalDebtHarness12073 {
	t.Helper()
	installFakeNetworkctl(t)
	h := &invalDebtHarness12073{}
	h.oldCfg = twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	h.newCfg = twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	h.webID = dpuserspace.PolicyIDsByStableKey(h.oldCfg)["trust->untrust/p-web"]
	if h.webID == 0 {
		t.Fatal("precondition: p-web must have a non-overloaded runtime id")
	}
	h.webSess = dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40001, DstPort: 80, Protocol: 6,
	}
	h.webSessV6 = dataplane.SessionKeyV6{
		SrcIP: [16]byte{0x20, 0x01, 15: 0x01}, DstIP: [16]byte{0x20, 0x01, 15: 0x02},
		SrcPort: 40003, DstPort: 80, Protocol: 6,
	}
	h.dp = &invalDebtTestDP12073{
		script:          script,
		relabelPolicyID: h.webID,
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			h.webSess: {State: dataplane.SessStateEstablished, PolicyID: h.webID},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			h.webSessV6: {State: dataplane.SessStateEstablished, PolicyID: h.webID},
		},
	}
	h.sender = cluster.NewSessionSync(":0", ":0", h.dp)
	h.sender.SetConnectedForTesting(true)
	h.recvDP = &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			h.webSess: {State: dataplane.SessStateEstablished, PolicyID: h.webID},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			h.webSessV6: {State: dataplane.SessStateEstablished, PolicyID: h.webID},
		},
	}
	h.receiver = cluster.NewSessionSync(":0", ":0", h.recvDP)
	h.d = &Daemon{
		applySem:    semaphore.NewWeighted(1),
		store:       newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:     vrrp.NewManager(),
		opts:        Options{NoDataplane: true},
		cluster:     newClusterManager(true),
		sessionSync: h.sender,
	}
	h.d.setDataplane(h.dp) // #2114: publish through the cell
	return h
}

func (h *invalDebtHarness12073) commit(oldCfg, newCfg *config.Config) error {
	if err := h.d.applySem.Acquire(context.Background(), 1); err != nil {
		return err
	}
	defer h.d.applySem.Release(1)
	_, err := h.d.applyAndSyncCommitted(oldCfg, newCfg, peerSyncNever)
	return err
}

func (h *invalDebtHarness12073) sessionsInstalled() bool {
	_, v4ok := h.dp.v4[h.webSess]
	_, v6ok := h.dp.v6[h.webSessV6]
	return v4ok && v6ok
}

func (h *invalDebtHarness12073) localDeleteCount() int {
	return len(h.dp.deletedV4) + len(h.dp.deletedV6)
}

// drainHASync applies the sender's queued messages to the receiver and
// returns their types. Mirrors TestDeleteInvalidatedSessionsErrorSyncsExactSet.
func (h *invalDebtHarness12073) drainHASync(t *testing.T) []string {
	t.Helper()
	types, err := h.sender.ApplyQueuedMessagesForTesting(h.receiver)
	if err != nil {
		t.Fatalf("apply queued delete messages: %v", err)
	}
	return types
}

// TestInvalidationDebtFailedPublishClearsAfterRetry12073: first ApplyConfig
// FAILS (#5679: OLD snapshot stays live). No policy-session delete may be
// issued then; when the retry lands, exactly one clear for the (old,new)
// pair runs — locally AND on the HA delete-sync.
func TestInvalidationDebtFailedPublishClearsAfterRetry12073(t *testing.T) {
	transient := errors.New("helper control socket: connection refused")
	h := newInvalDebtHarness12073(t, []invalDebtOutcome12073{{err: transient}})

	if err := h.commit(h.oldCfg, h.newCfg); err == nil {
		t.Fatal("failed dataplane publish must fail the commit (#5679), got nil")
	}
	if h.dp.applyCalls != 1 {
		t.Fatalf("apply calls = %d, want 1", h.dp.applyCalls)
	}
	if !h.sessionsInstalled() {
		t.Fatalf("FAILED publish cleared %d session(s) against the still-live OLD policy; "+
			"the (old,new) pair must persist as invalidation debt until the first successful publish",
			h.localDeleteCount())
	}

	// The operator re-commits / the retry owner re-applies the same pair;
	// this time the publish lands.
	if err := h.commit(h.oldCfg, h.newCfg); err != nil {
		t.Fatalf("retrying commit: %v", err)
	}
	if h.sessionsInstalled() {
		t.Fatal("retry publish landed but the (old,new) invalidation debt was never discharged; " +
			"the deleted policy's sessions keep forwarding under stale authorization")
	}
	if got := h.localDeleteCount(); got != 2 {
		t.Fatalf("local deletes after landing = %d, want exactly 2 (one v4 + one v6) for the (old,new) pair", got)
	}
	types := h.drainHASync(t)
	if len(types) != 2 || types[0] != "delete_v4" || types[1] != "delete_v6" {
		t.Fatalf("HA delete-sync message types = %v, want [delete_v4 delete_v6]", types)
	}
	if _, ok := h.recvDP.v4[h.webSess]; ok {
		t.Fatal("HA peer still holds the v4 session after the delete-sync")
	}
	if _, ok := h.recvDP.v6[h.webSessV6]; ok {
		t.Fatal("HA peer still holds the v6 session after the delete-sync")
	}
}

// TestInvalidationDebtBareRetryDischargesOnLanding12073 covers #9811's
// background retry, which has no commit caller to run the clear itself.
func TestInvalidationDebtBareRetryDischargesOnLanding12073(t *testing.T) {
	transient := errors.New("helper control socket: connection refused")
	h := newInvalDebtHarness12073(t, []invalDebtOutcome12073{{err: transient}})
	if err := h.commit(h.oldCfg, h.newCfg); err == nil {
		t.Fatal("first failed publish must return an error")
	}
	if !h.sessionsInstalled() {
		t.Fatal("failed publish must retain sessions until the retry lands")
	}

	if err := h.d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("acquire apply semaphore: %v", err)
	}
	err := h.d.applyConfigLocked(context.Background(), h.newCfg)
	h.d.applySem.Release(1)
	if err != nil {
		t.Fatalf("bare retry: %v", err)
	}
	if h.sessionsInstalled() {
		t.Fatal("bare retry landed but did not discharge the retained invalidation debt")
	}
	if got := h.localDeleteCount(); got != 2 {
		t.Fatalf("local deletes after bare retry = %d, want exactly 2", got)
	}
	types := h.drainHASync(t)
	if len(types) != 2 || types[0] != "delete_v4" || types[1] != "delete_v6" {
		t.Fatalf("HA delete-sync message types = %v, want [delete_v4 delete_v6]", types)
	}
}

// TestInvalidationDebtDeferredPublishClearsAfterLanding12073: first
// ApplyConfig SUCCEEDS but defers its publish (XSK startup:
// SnapshotPublishDeferred — the helper still serves the previous snapshot).
// No policy-session delete may be issued then; when the landing publish
// arrives, exactly one clear for the (old,new) pair runs — locally AND on
// the HA delete-sync.
func TestInvalidationDebtDeferredPublishClearsAfterLanding12073(t *testing.T) {
	h := newInvalDebtHarness12073(t, []invalDebtOutcome12073{{deferred: true}})

	if err := h.commit(h.oldCfg, h.newCfg); err != nil {
		t.Fatalf("deferred publish still commits clean, got %v", err)
	}
	if !h.sessionsInstalled() {
		t.Fatalf("DEFERRED publish cleared %d session(s) against the still-live OLD policy; "+
			"the (old,new) pair must persist as invalidation debt until the publish lands",
			h.localDeleteCount())
	}

	// A helper session admitted under the still-live old snapshot during XSK
	// startup must be captured immediately before the status-loop publish,
	// not omitted by the initial deferred-apply capture.
	lateV4 := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 3}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40005, DstPort: 443, Protocol: 6,
	}
	lateV6 := dataplane.SessionKeyV6{
		SrcIP: [16]byte{0x20, 0x01, 15: 0x03}, DstIP: [16]byte{0x20, 0x01, 15: 0x02},
		SrcPort: 40007, DstPort: 443, Protocol: 6,
	}
	h.dp.v4[lateV4] = dataplane.SessionValue{State: dataplane.SessStateEstablished, PolicyID: h.webID}
	h.dp.v6[lateV6] = dataplane.SessionValueV6{State: dataplane.SessStateEstablished, PolicyID: h.webID}
	h.recvDP.v4[lateV4] = dataplane.SessionValue{State: dataplane.SessStateEstablished, PolicyID: h.webID}
	h.recvDP.v6[lateV6] = dataplane.SessionValueV6{State: dataplane.SessStateEstablished, PolicyID: h.webID}
	generation := h.dp.lastApply.Generation
	if err := h.d.capturePolicyInvalidationBeforeDeferredPublish(generation); err != nil {
		t.Fatalf("pre-publish status capture: %v", err)
	}
	if h.localDeleteCount() != 0 {
		t.Fatalf("pre-publish capture issued %d deletes before the snapshot landed", h.localDeleteCount())
	}
	// The actual publish re-stamps the deleted policy's live rows to the
	// default-policy sentinel; only a candidate set captured before this point
	// can still find and delete them.
	h.dp.relabelDeletedPolicySessions()
	// This is the generation-matched success notification from the manager's
	// post-publish capture-authority callback.
	h.d.dischargePolicyInvalidationAfterPublish(generation)

	if h.sessionsInstalled() {
		t.Fatal("deferred landing left the original deleted-policy sessions installed")
	}
	if _, ok := h.dp.v4[lateV4]; ok {
		t.Fatal("deferred landing left a session admitted during XSK startup installed")
	}
	if _, ok := h.dp.v6[lateV6]; ok {
		t.Fatal("deferred landing left a v6 session admitted during XSK startup installed")
	}
	if got := h.localDeleteCount(); got != 4 {
		t.Fatalf("local deletes after deferred landing = %d, want exactly 4 (two v4 + two v6)", got)
	}
	types := h.drainHASync(t)
	gotTypes := map[string]int{}
	for _, typ := range types {
		gotTypes[typ]++
	}
	if len(types) != 4 || gotTypes["delete_v4"] != 2 || gotTypes["delete_v6"] != 2 {
		t.Fatalf("HA delete-sync message types = %v, want two delete_v4 + two delete_v6", types)
	}
	if _, ok := h.recvDP.v4[h.webSess]; ok {
		t.Fatal("HA peer still holds the original v4 session after deferred landing")
	}
	if _, ok := h.recvDP.v6[h.webSessV6]; ok {
		t.Fatal("HA peer still holds the original v6 session after deferred landing")
	}
	if _, ok := h.recvDP.v4[lateV4]; ok {
		t.Fatal("HA peer still holds the late v4 session after deferred landing")
	}
	if _, ok := h.recvDP.v6[lateV6]; ok {
		t.Fatal("HA peer still holds the late v6 session after deferred landing")
	}
}

// TestInvalidationDebtSupersedingCommitMergesDebt12073: a commit that lands
// while an earlier pair's debt is still owed must not strand it — the debt
// merges to (oldest-uninvalidated, newest-landing) and clears once.
func TestInvalidationDebtSupersedingCommitMergesDebt12073(t *testing.T) {
	transient := errors.New("helper control socket: connection refused")
	h := newInvalDebtHarness12073(t, []invalDebtOutcome12073{{err: transient}})

	if err := h.commit(h.oldCfg, h.newCfg); err == nil {
		t.Fatal("failed dataplane publish must fail the commit (#5679), got nil")
	}
	if !h.sessionsInstalled() {
		t.Fatal("failed publish must not clear against the still-live OLD policy")
	}

	// A superseding commit (an unrelated change on top) lands. Its own
	// (C2,C3) diff has no policy deletion, but the stranded (C1,C2) debt
	// must still discharge — merged as (C1,C3).
	c3 := twoPolicyConfig([]string{"p-first", "p-ssh", "p-extra"}, nil)
	if err := h.commit(h.newCfg, c3); err != nil {
		t.Fatalf("superseding commit: %v", err)
	}
	if h.sessionsInstalled() {
		t.Fatal("superseding landing publish did not discharge the stranded (C1,C2) debt; " +
			"the deleted policy's sessions keep forwarding under stale authorization")
	}
	if got := h.localDeleteCount(); got != 2 {
		t.Fatalf("local deletes after superseding landing = %d, want exactly 2", got)
	}
}

// TestInvalidationDebtLandedSuccessClearsImmediately12073: the normal path is
// unchanged — a publish that lands clears in the same commit (once).
func TestInvalidationDebtLandedSuccessClearsImmediately12073(t *testing.T) {
	h := newInvalDebtHarness12073(t, nil) // every publish lands
	if err := h.commit(h.oldCfg, h.newCfg); err != nil {
		t.Fatalf("applyAndSyncCommitted: %v", err)
	}
	if h.sessionsInstalled() {
		t.Fatal("landed publish did not clear the deleted policy's sessions in the same commit")
	}
	if got := h.localDeleteCount(); got != 2 {
		t.Fatalf("local deletes = %d, want exactly 2 (one v4 + one v6)", got)
	}
	types := h.drainHASync(t)
	if len(types) != 2 || types[0] != "delete_v4" || types[1] != "delete_v6" {
		t.Fatalf("HA delete-sync message types = %v, want [delete_v4 delete_v6]", types)
	}

	// A second landing commit of an unrelated change must not re-clear: the
	// debt discharged exactly once.
	c3 := twoPolicyConfig([]string{"p-first", "p-ssh", "p-extra"}, nil)
	if err := h.commit(h.newCfg, c3); err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if got := h.localDeleteCount(); got != 2 {
		t.Fatalf("local deletes after an unrelated second commit = %d, want still 2 (exactly-once discharge)", got)
	}
}
