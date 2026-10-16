package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type persistentNatGenerationHelper11486 struct {
	requests chan ControlRequest
	listener net.Listener
}

func startPersistentNatGenerationHelper11486(t *testing.T, socket string) *persistentNatGenerationHelper11486 {
	t.Helper()
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen helper control socket: %v", err)
	}
	helper := &persistentNatGenerationHelper11486{
		requests: make(chan ControlRequest, 16),
		listener: listener,
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req ControlRequest
				if json.NewDecoder(conn).Decode(&req) != nil {
					return
				}
				helper.requests <- req
				resp := ControlResponse{OK: true}
				if req.Type == "clear_persistent_nat_leases" {
					resp.PersistentNatLeaseCount = 3
				}
				_ = json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()
	return helper
}

func persistentNatGenerationManager11486(t *testing.T, path string) (*Manager, *persistentNatGenerationHelper11486) {
	t.Helper()
	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = filepath.Join(t.TempDir(), "control.sock")
	m.persistentNatLeaseGenerationPath = path
	m.helperStatusObserved = true
	m.lastStatus.ConfigSnapshotProtocolVersion = MinProtocolPersistentNatLeasePermissions
	return m, startPersistentNatGenerationHelper11486(t, m.cfg.ControlSocket)
}

func TestPersistentNatClearGenerationSurvivesManagerRestart11486(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	m, helper := persistentNatGenerationManager11486(t, path)
	count, origin, generation, err := m.ClearPersistentNATLeasesWithGeneration("", 0)
	if err != nil {
		t.Fatalf("clear persistent NAT: %v", err)
	}
	if count != 3 || generation != 2 || len(origin) != 32 {
		t.Fatalf("clear result = count %d origin %q generation %d", count, origin, generation)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("helper request = %q, want authoritative clear", got)
	}

	restarted, restartHelper := persistentNatGenerationManager11486(t, path)
	batch, err := restarted.ExportPersistentNatLeaseBatch()
	if err != nil {
		t.Fatalf("export after manager restart: %v", err)
	}
	if batch.OriginID != origin || batch.Generation != generation {
		t.Fatalf("restarted batch origin/generation = %q/%d, want %q/%d",
			batch.OriginID, batch.Generation, origin, generation)
	}
	if len(batch.Leases) != 0 {
		t.Fatalf("empty helper export returned %d leases", len(batch.Leases))
	}
	if got := (<-restartHelper.requests).Type; got != "export_idle_leases" {
		t.Fatalf("restart helper request = %q, want export_idle_leases", got)
	}
}

func TestPersistentNatDelayedImportRejected11486(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	m, helper := persistentNatGenerationManager11486(t, path)
	batch := PersistentNatLeaseBatch{
		OriginID:   "0123456789abcdef0123456789abcdef",
		Generation: 8,
		Leases:     []IdleLeaseWire{scopedLease10018()},
	}
	if err := m.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("import generation 8: %v", err)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("generation 8 helper request = %q, want clear_persistent_nat_leases", got)
	}
	if req := <-helper.requests; req.Type != "import_idle_leases" || !req.ClearGenerationValidated {
		t.Fatalf("generation 8 helper import = %+v, want generation-validated import_idle_leases", req)
	}

	restarted, staleHelper := persistentNatGenerationManager11486(t, path)
	batch.Generation = 7
	if err := restarted.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("delayed generation 7 import should be rejected without error: %v", err)
	}
	select {
	case req := <-staleHelper.requests:
		t.Fatalf("delayed pre-clear batch reached helper as %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}

	batch.Generation = 8
	if err := restarted.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("same-generation additive import: %v", err)
	}
	if req := <-staleHelper.requests; req.Type != "import_idle_leases" || !req.ClearGenerationValidated {
		t.Fatalf("same-generation helper import = %+v, want generation-validated import_idle_leases", req)
	}
}

func TestPersistentNatEmptyBatchCarriesAndPersistsClearBarrier11486(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	m, helper := persistentNatGenerationManager11486(t, path)
	batch := PersistentNatLeaseBatch{
		OriginID:   "0123456789abcdef0123456789abcdef",
		Generation: 9,
	}
	if err := m.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("empty generation 9 batch: %v", err)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("empty new-generation batch request = %q, want clear", got)
	}
	if got := len(helper.requests); got != 0 {
		t.Fatalf("empty batch issued %d extra helper requests", got)
	}

	restarted, staleHelper := persistentNatGenerationManager11486(t, path)
	batch.Generation = 8
	batch.Leases = []IdleLeaseWire{scopedLease10018()}
	if err := restarted.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("delayed pre-clear batch: %v", err)
	}
	if got := len(staleHelper.requests); got != 0 {
		t.Fatalf("persisted generation barrier allowed %d stale helper requests", got)
	}
}
func TestPersistentNatGenerationOneClearsBeforeFirstAdvertisement11486(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	m, helper := persistentNatGenerationManager11486(t, path)
	batch, err := m.ExportPersistentNatLeaseBatch()
	if err != nil {
		t.Fatalf("first generation export: %v", err)
	}
	if batch.Generation != 1 || len(batch.OriginID) != 32 {
		t.Fatalf("first batch origin/generation = %q/%d, want origin and generation 1",
			batch.OriginID, batch.Generation)
	}
	for _, want := range []string{"clear_persistent_nat_leases", "export_idle_leases"} {
		if got := (<-helper.requests).Type; got != want {
			t.Fatalf("first generation helper request = %q, want %q", got, want)
		}
	}
}

func TestPersistentNatGenerationZeroDoesNotImplyClear11486(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	m, helper := persistentNatGenerationManager11486(t, path)
	if _, _, _, err := m.ClearPersistentNATLeasesWithGeneration("", 0); err != nil {
		t.Fatalf("initialize local replay floor: %v", err)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("initialize helper request = %q, want local clear", got)
	}
	batch := PersistentNatLeaseBatch{
		OriginID: "0123456789abcdef0123456789abcdef",
		Leases:   []IdleLeaseWire{scopedLease10018()},
	}
	if err := m.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("import initial generation-zero batch: %v", err)
	}
	if got := (<-helper.requests).Type; got != "import_idle_leases" {
		t.Fatalf("initial generation-zero request = %q, want additive import", got)
	}
	select {
	case req := <-helper.requests:
		t.Fatalf("generation-zero import unexpectedly cleared local leases via %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}
}

func TestExpiredLocalClearFenceAdmitsSameGeneration13909(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	const origin = "0123456789abcdef0123456789abcdef"
	const local = "fedcba9876543210fedcba9876543210"
	expiredState := struct {
		OriginID                       string            `json:"origin_id"`
		Generation                     uint64            `json:"generation"`
		RemoteGenerations              map[string]uint64 `json:"remote_generations"`
		LocalClearRemoteGenerations    map[string]uint64 `json:"local_clear_remote_generations"`
		LocalClearRemoteGenerationEnds map[string]int64  `json:"local_clear_remote_generation_ends"`
	}{
		OriginID: local, Generation: 4,
		RemoteGenerations:              map[string]uint64{origin: 8},
		LocalClearRemoteGenerations:    map[string]uint64{origin: 8},
		LocalClearRemoteGenerationEnds: map[string]int64{origin: time.Now().Add(-time.Second).UnixNano()},
	}
	data, err := json.Marshal(expiredState)
	if err != nil {
		t.Fatalf("marshal expired fence state: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write expired fence state: %v", err)
	}
	m, helper := persistentNatGenerationManager11486(t, path)
	if err := m.ImportPersistentNatLeaseBatch(PersistentNatLeaseBatch{
		OriginID: origin, Generation: 8, Leases: []IdleLeaseWire{scopedLease10018()},
	}); err != nil {
		t.Fatalf("import same-generation post-expiry lease: %v", err)
	}
	select {
	case req := <-helper.requests:
		if req.Type != "import_idle_leases" {
			t.Fatalf("expired-fence import = %+v, want import_idle_leases", req)
		}
	case <-time.After(25 * time.Millisecond):
		t.Fatal("expired fence continued rejecting same-generation lease batch")
	}
	restarted, staleHelper := persistentNatGenerationManager11486(t, path)
	if err := restarted.ImportPersistentNatLeaseBatch(PersistentNatLeaseBatch{
		OriginID: origin, Generation: 7, Leases: []IdleLeaseWire{scopedLease10018()},
	}); err != nil {
		t.Fatalf("import stale generation after fence expiry and restart: %v", err)
	}
	select {
	case req := <-staleHelper.requests:
		t.Fatalf("stale generation reached helper after fence expiry as %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}
}

// #13909: a local clear fences delayed same-generation batches only for a
// bounded interval. A peer that does not clear must eventually be able to
// advertise leases created after this node's clear.
func TestLocalClearFenceExpiresWithoutPeerClear13909(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	const origin = "0123456789abcdef0123456789abcdef"
	m, helper := persistentNatGenerationManager11486(t, path)
	now := time.Unix(1_800_000_000, 0)
	m.persistentNatLeaseNowFn = func() time.Time { return now }

	batch := PersistentNatLeaseBatch{OriginID: origin, Generation: 8}
	if err := m.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("import empty generation 8: %v", err)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("generation 8 first request = %q, want clear", got)
	}
	if _, _, _, err := m.ClearPersistentNATLeasesWithGeneration("", 0); err != nil {
		t.Fatalf("local clear: %v", err)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("local clear helper request = %q, want clear", got)
	}

	batch.Leases = []IdleLeaseWire{scopedLease10018()}
	if err := m.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("same-generation batch inside fence: %v", err)
	}
	select {
	case req := <-helper.requests:
		t.Fatalf("same-generation batch reached helper before fence expiry as %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}

	now = now.Add(persistentNatLocalClearFenceLifetime + time.Nanosecond)
	if err := m.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("same-generation batch after fence expiry: %v", err)
	}
	if req := <-helper.requests; req.Type != "import_idle_leases" {
		t.Fatalf("same-generation batch after expiry = %+v, want import_idle_leases", req)
	}
	if len(m.persistentNatLeaseGeneration.LocalClearRemoteGenerations) != 0 ||
		len(m.persistentNatLeaseGeneration.LocalClearRemoteGenerationEnds) != 0 {
		t.Fatalf("expired fence was not pruned: %+v", m.persistentNatLeaseGeneration)
	}
}

func TestLocalClearFenceDoesNotBlockNewOrigin13909(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	const knownOrigin = "0123456789abcdef0123456789abcdef"
	const newOrigin = "fedcba9876543210fedcba9876543210"
	m, helper := persistentNatGenerationManager11486(t, path)
	if err := m.ImportPersistentNatLeaseBatch(PersistentNatLeaseBatch{
		OriginID: knownOrigin, Generation: 8,
	}); err != nil {
		t.Fatalf("import known peer: %v", err)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("known peer barrier = %q, want clear", got)
	}
	if _, _, _, err := m.ClearPersistentNATLeasesWithGeneration("", 0); err != nil {
		t.Fatalf("local clear: %v", err)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("local clear helper request = %q, want clear", got)
	}

	if err := m.ImportPersistentNatLeaseBatch(PersistentNatLeaseBatch{
		OriginID: newOrigin, Generation: 1, Leases: []IdleLeaseWire{scopedLease10018()},
	}); err != nil {
		t.Fatalf("import newly observed peer after local clear: %v", err)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("new peer generation barrier = %q, want clear", got)
	}
	if req := <-helper.requests; req.Type != "import_idle_leases" {
		t.Fatalf("new peer lease import = %+v, want import_idle_leases", req)
	}
}

// #13867: a local clear revokes leases from every origin, so it must also
// close the admission door to pre-clear equal-generation batches — including
// leases whose key was not installed at clear time (therefore has no Rust
// per-key tombstone) — while a peer that clears at a newer generation reopens
// admission for genuinely post-clear leases.
func TestLocalClearEqualGenerationFence13867(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	const origin = "0123456789abcdef0123456789abcdef"
	m, helper := persistentNatGenerationManager11486(t, path)

	batch := PersistentNatLeaseBatch{OriginID: origin, Generation: 8}
	if err := m.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("import empty generation 8: %v", err)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("generation 8 first request = %q, want clear", got)
	}

	// A local clear revokes every lease in the helper and must fence later
	// equal-generation imports.
	if _, _, _, err := m.ClearPersistentNATLeasesWithGeneration("", 0); err != nil {
		t.Fatalf("local clear: %v", err)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("local clear helper request = %q, want clear", got)
	}

	// Delayed pre-clear batch: same generation 8, containing a lease key
	// never installed locally, so no per-key tombstone exists for it.
	batch.Leases = []IdleLeaseWire{scopedLease10018()}

	if err := m.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("delayed equal-generation import: %v", err)
	}
	select {
	case req := <-helper.requests:
		t.Fatalf("delayed equal-generation batch reached helper as %q after local clear", req.Type)
	case <-time.After(25 * time.Millisecond):
	}

	// The fence must survive a daemon restart via durable state.
	restarted, restartHelper := persistentNatGenerationManager11486(t, path)
	if err := restarted.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("delayed equal-generation import after restart: %v", err)
	}
	select {
	case req := <-restartHelper.requests:
		t.Fatalf("post-restart delayed batch reached helper as %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}
	batch.Generation = 7
	if err := restarted.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("older-generation import: %v", err)
	}
	select {
	case req := <-restartHelper.requests:
		t.Fatalf("older-generation batch reached helper as %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}

	// A genuinely post-clear batch advances the watermark: generation 9 must
	// clear-and-import, preserving post-clear subscriber import behavior.
	batch.Generation = 9
	if err := restarted.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("post-clear generation 9 import: %v", err)
	}
	if got := (<-restartHelper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("generation 9 first request = %q, want clear", got)
	}
	if req := <-restartHelper.requests; req.Type != "import_idle_leases" || !req.ClearGenerationValidated {
		t.Fatalf("generation 9 import = %+v, want generation-validated import", req)
	}
	if err := restarted.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("post-clear equal-generation import: %v", err)
	}
	if req := <-restartHelper.requests; req.Type != "import_idle_leases" {
		t.Fatalf("post-clear equal-generation request = %+v, want additive import", req)
	}
}

func TestLegacyPersistentNatGenerationStateLoads13867(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	const origin = "0123456789abcdef0123456789abcdef"
	const remote = "fedcba9876543210fedcba9876543210"
	// This is the pre-#13867 durable shape: the new clear watermark field is
	// absent and must decode as an empty map, not invalidate existing state.
	legacy, err := json.Marshal(struct {
		OriginID          string            `json:"origin_id"`
		Generation        uint64            `json:"generation"`
		RemoteGenerations map[string]uint64 `json:"remote_generations,omitempty"`
		PendingLocalClear bool              `json:"pending_local_clear,omitempty"`
		PendingRemote     map[string]bool   `json:"pending_remote,omitempty"`
	}{
		OriginID: origin, Generation: 4,
		RemoteGenerations: map[string]uint64{remote: 7},
	})
	if err != nil {
		t.Fatalf("marshal legacy state: %v", err)
	}
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}
	m := New()
	m.persistentNatLeaseGenerationPath = path
	if err := m.loadPersistentNatLeaseGenerationLocked(); err != nil {
		t.Fatalf("load legacy state: %v", err)
	}
	state := m.persistentNatLeaseGeneration
	remoteGeneration, remotePresent := state.RemoteGenerations[remote]
	if state.OriginID != origin || state.Generation != 4 ||
		!remotePresent || remoteGeneration != 7 ||
		len(state.LocalClearRemoteGenerations) != 0 {
		t.Fatalf("loaded legacy state = %+v", state)
	}
}
