// Package configstore implements the Junos-style candidate/active
// configuration management with commit and rollback support.
//
// The Store type is split across several same-package files for
// readability (#2158 code-motion, no behavior change):
//   - store.go         — Store struct, New, node/cluster accessors, the
//     compile/schema-validate pipeline, SyncApply
//   - store_persist.go — Load/Save, writeActive*, journal helpers, the
//     #1799 degrade-and-retry persist machinery,
//     config archival, and rescue config
//   - store_lock.go    — config-mode enter/exit locking + edit-path nav
//   - store_command.go — candidate edit verbs (set/delete/copy/...) and
//     the flat-line replay (LoadSet/LoadMerge/...)
//   - store_commit.go  — commit / commit-confirmed / rollback, the
//     confirm-timer machinery, and rollback-history
//     file persistence
//   - store_format.go  — the Show* render family + read-only accessors
package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore/journal"
)

// JournalEntry is the audit-log record type, owned by the journal
// subpackage since #1896 (compact v2 entries: no config payloads —
// full trees live in the rollback slots; see journal.Entry).
type JournalEntry = journal.Entry

// MaxConfigSize bounds a single configuration payload accepted by any parse
// entry point: LoadOverride, LoadMerge, LoadSet, and the HA SyncApply ingress.
// Real configurations are well under 1 MiB; this generous 16 MiB ceiling
// rejects a hostile or corrupt payload with a clean error before the parser
// runs, so a pathological input cannot exhaust memory or (together with the
// pkg/config lexer/depth guards) the goroutine stack. It is the
// transport-independent backstop for the grpc.MaxRecvMsgSize / http
// .MaxBytesReader caps, covering any caller — a future one, or an HA peer —
// that reaches these methods without passing through the gRPC/REST limits
// (fable-review-164 H-2).
const MaxConfigSize = 16 << 20 // 16 MiB

// checkConfigSize rejects an over-large payload before it reaches the parser.
func checkConfigSize(content string) error {
	if len(content) > MaxConfigSize {
		return fmt.Errorf("config too large: %d bytes exceeds maximum %d bytes",
			len(content), MaxConfigSize)
	}
	return nil
}

// Store manages the candidate and active configuration.
type Store struct {
	mu        sync.RWMutex
	active    *config.ConfigTree
	candidate *config.ConfigTree
	compiled  *config.Config // compiled active config
	history   *History
	dirty     bool
	configDir bool // true if in configuration mode
	filePath  string

	// candidateGen is a MONOTONIC token that changes whenever the candidate
	// tree changes identity or content — every set/delete/load/rename/copy/
	// insert/annotate/(de)activate mutation, every rollback, every
	// enter/exit/reclaim of configuration mode, the peer-sync candidate reset,
	// and the post-commit candidate reset. It backs the #5848 generation-bound
	// commit transaction: the daemon snapshots+compiles the candidate and reads
	// this token atomically (CompileCandidateGen), runs its external
	// device-map hardware pre-flight on that immutable snapshot OUTSIDE the store
	// lock, then commits ONLY if the token is unchanged (CommitWithDescriptionGen
	// / CommitConfirmedGen). A concurrent candidate edit between snapshot and
	// promote bumps the token, so the commit returns
	// ErrCandidateGenerationConflict instead of silently promoting an unexamined
	// generation. It is authoritative over content: a candidate edited and then
	// reverted to byte-identical content still yields a new token (the examined
	// generation is gone), so the conservative outcome is a conflict/retry.
	// ALWAYS bumped via bumpCandidateGenLocked under s.mu.Lock.
	candidateGen uint64

	// Persistent storage
	db      *DB
	journal *journal.Journal

	// writeActiveFn is a test seam for active-config persistence
	// (#1799). nil (production) means s.db.WriteActive. Set via
	// SetWriteActiveForTesting; never assigned on production paths.
	writeActiveFn func(*config.ConfigTree) error

	// writeActiveMarkerFn is the marker-aware test seam for the #1922
	// step-0 committed marker. nil (production) routes to
	// db.WriteActiveMarker. Set via SetWriteActiveMarkerForTesting.
	writeActiveMarkerFn func(*config.ConfigTree, bool) error

	// everCommitted is the #1922 step-0 marker as loaded/observed in
	// memory: true once a config has been successfully committed or
	// synced to this store (or loaded from a committed/legacy DB), false
	// on a fresh store and after the Item 1b first-commit rollback writes
	// the never-committed marker. The boot predicate (BootClassify) reads
	// it to disambiguate operator-committed-empty (normal) from
	// never-committed (bootstrap). Default false on a new Store; Load sets
	// it from the on-disk envelope marker (absent/legacy DB => true).
	everCommitted bool

	// #1799 Option B (degrade-not-fail) state for the persist paths
	// that must proceed in memory even when the disk write fails
	// (SyncApply HA convergence, performAutoRollback safety revert).
	// persistDegraded is surfaced via ConfigPersistDegraded() to the
	// /health 503 check and the xpf_daemon_config_persist_degraded
	// gauge. persistRetryActive is the singleton guard for the
	// background retry goroutine (exactly one loop at a time). The
	// backoff fields are test seams; zero means the production
	// defaults (1s initial, doubling to a 60s cap).
	persistDegraded            bool
	persistRetryActive         bool
	persistRetryInitialBackoff time.Duration
	// persistRefusedTree is the active tree the persist retry loop last saw
	// refused by the read ceiling (#9617). The loop does not re-attempt that
	// tree; any promotion installs a new tree object and resumes retries.
	// Guarded by mu.
	persistRefusedTree     *config.ConfigTree
	persistRetryMaxBackoff time.Duration

	// persistMarkerCommitted records the #1922 step-0 committed flag the
	// degraded-persist retry loop must re-write. Defaults true; set false
	// ONLY by the Item 1b first-commit rollback so a FAILED never-committed
	// marker write that later heals via the retry loop persists committed=0
	// (never-committed), NOT committed=1 — otherwise a restart would
	// misclassify the rolled-back box as operator-committed-empty (normal)
	// and take over interfaces on an empty config (Codex r1 release-blocker).
	// Every successful committed write resets it to true.
	persistMarkerCommitted bool

	// confirmResolvePendingPersist records that a commit-confirmed window was
	// RESOLVED in memory (timeout auto-rollback, boot recovery, or an HA
	// config-sync that superseded it) but the resolving active-config write
	// FAILED, so confirm.json — the crash-recovery record that re-drives the
	// rollback/replacement to its target — must NOT be removed yet (#5473).
	// The durable-transition invariant: the recovery record survives until the
	// replacement config is DURABLE on disk, so a crash before the degraded
	// retry heals boots into a state that RE-RUNS the rollback rather than
	// stranding the pre-rollback config with no record. Cleared (and confirm.json
	// removed) by the next durable active write — the persist-retry heal or any
	// superseding commit/sync — via clearConfirmResolutionPendingLocked. Default
	// false; only the degrade-not-fail resolution paths set it.
	confirmResolvePendingPersist bool

	// confirmRemoveDegraded records that a RESOLVED pending commit-confirmed
	// window's confirm.json REMOVAL failed to become durable (#5835): either the
	// unlink failed, or the post-unlink parent-dir fsync failed so the dirent
	// removal is not yet durable on disk. UNLIKE confirmResolvePendingPersist
	// (which waits for a replacement active WRITE to land before removing the
	// record) this is a debt to re-run DeleteConfirm itself — the resolving
	// config is already durable, but the stale crash-recovery record still
	// lingers and a crash+restart could resurrect its rollback of an
	// already-confirmed config. This is the operation state that distinguishes
	// "removal durable / never existed" (false) from "unlink succeeded, dir sync
	// still owed" (true), so an absent-file retry re-drives the #4864 dir fsync
	// rather than reporting a false success. Surfaced via ConfigPersistDegraded()
	// (and ConfirmRemovalDegraded()) until the singleton persist-retry loop lands
	// the removal durably. Default false.
	confirmRemoveDegraded bool

	// confirmRecoveryReadFailed records that boot recovery could NOT READ
	// confirm.json (#8566): the file exists but the read, the decrypt, or the
	// #5637 structural validation failed. `Load` still SUCCEEDS — a corrupt
	// transient recovery file must not brick a boot (#1960) — but the pending
	// commit-confirmed rollback window is GONE for the lifetime of this process:
	// no timer is armed and the still-UNCONFIRMED config now stands
	// indefinitely, which is exactly the #4577 failure the record exists to
	// prevent. Before this flag that outcome was reported by a single WARN line
	// and nothing else: `ConfigPersistDegraded()` was false, so /health returned
	// 200 and `xpf_daemon_config_persist_degraded` read 0. The box came up
	// looking fine.
	//
	// The record is deliberately NOT deleted — a decrypt failure can be a
	// transient master-key problem and the window may be readable on a later
	// boot — so this state clears on operator action instead: the next
	// successful arm or removal of a confirm record.
	confirmRecoveryReadFailed bool

	// confirmRemoveDebtID identifies WHICH commit-confirmed record the two
	// removal debts above are owed for (#7675). Both debts used to be UNKEYED:
	// the retry loop and the deferred finalize called DeleteConfirm()
	// unconditionally, deleting whatever confirm.json happened to be on disk.
	// An operator who armed a BRAND-NEW `commit confirmed` while a debt was
	// outstanding therefore had the NEW window's crash-recovery file deleted by
	// a retry that believed it was clearing the old one — measured deterministic
	// on master, not a race: the in-memory timer stays armed so nothing looks
	// wrong, and a restart before the new deadline then leaves the UNCONFIRMED
	// config standing with no rollback, the exact #4577 failure the record
	// exists to prevent. A newer arm durably REPLACES the file
	// (WriteConfirm is temp+fsync+rename+dir-fsync), so the older record is
	// already gone and its removal debt is satisfied by construction: the retry
	// clears the debt instead of deleting. Empty when no debt is held, or when
	// the record could not be identified at debt time (already unlinked with the
	// directory barrier still owed) — in which case ANY present readable record
	// is a newer one and must not be deleted.
	confirmRemoveDebtID string

	// Commit confirmed state. confirmGen is a generation token
	// guarding the auto-rollback callback against staleness: a timer
	// that has already fired and is blocked on s.mu when a nested
	// CommitConfirmed (or ConfirmCommit) supersedes it must become a
	// no-op — time.Timer.Stop() cannot un-fire a callback that has
	// started (Codex review on PR #1817). Every arm/confirm bumps the
	// generation; the callback carries the value at arm time and
	// performAutoRollback rejects mismatches.
	confirmGen   uint64
	confirmTimer *time.Timer
	// confirmArmDegraded records that the ARM write (confirm.json) failed, so
	// the pending auto-rollback would not survive a crash (#9014). It was the
	// ONE confirm-durability leg with no health state: the write logged a
	// single slog.Warn and returned, CommitConfirmed still reported success,
	// and /health stayed 200 while a crash inside the window would leave the
	// unconfirmed configuration standing permanently. Its two neighbours --
	// confirmRecoveryReadFailed (#8566) and confirmRemoveDegraded (#5835) --
	// both raise health, journal, and (for the removal) self-heal.
	//
	// confirmArmGen pins WHICH window the debt belongs to. Re-driving the write
	// after the window was confirmed or rolled back would RESURRECT a
	// crash-recovery record for a window that no longer exists -- the mirror of
	// the #7675 hazard on the removal side, where re-driving a delete would have
	// removed a LIVE window's record.
	confirmArmDegraded bool
	confirmArmRec      *confirmRecord
	confirmArmGen      uint64
	confirmPrevTree    *config.ConfigTree // active tree before confirmed commit
	confirmPrevCfg     *config.Config     // compiled config before confirmed commit
	// confirmPrevFirst records whether confirmPrevTree is the EMPTY BOOTSTRAP
	// TREE — i.e. the pending commit-confirmed was the first commit on a fresh
	// store, so its rollback must re-enter never-committed state (#1922 Item
	// 1b: committed=0 marker, everCommitted cleared).
	//
	// #6538: this used to be DERIVED from `confirmPrevCfg == nil` at each
	// consumer. That nil carries two unrelated meanings — "there was no
	// compiled config to stash because this genuinely is the first commit" and
	// "the recovered rollback target failed even the lenient compile"
	// (recoverPendingConfirmLocked) — and the action taken on the first is
	// destructive for the second: committed=0 persisted over a REAL config, so
	// the next restart re-classifies the box into bootstrap (day-0 /
	// claim-all). Recording the fact at the moment it is known, instead of
	// inferring it later from a value that means two things, is what makes the
	// two states distinguishable to every consumer.
	confirmPrevFirst bool

	// rollbackExecutor is the daemon-registered transaction that owns
	// the WHOLE commit-confirmed timeout rollback (#1922 Item 1a). When
	// set, the auto-rollback timer hands it the confirm generation and
	// the executor acquires the daemon's apply semaphore FIRST, then
	// calls PromoteRollback (store-state promotion) + the dataplane
	// re-apply inside that one critical section. This makes promotion and
	// re-apply atomic with respect to a concurrent commit (which also
	// holds applySem), closing the store-vs-kernel split-brain window of
	// the old centralRollbackFn callback. It also wires the rollback in
	// SERVICE mode (gRPC/REST/remote-cli), where no interactive CLI.Run
	// ever registered the old callback. When nil (tests, non-daemon
	// embedders such as the standalone `cli` binary) the timer falls back
	// to performAutoRollback, which stays self-contained and correct for
	// that path.
	rollbackExecutor func(gen uint64)

	// Exclusive configuration mode
	exclusiveHolder string // who holds exclusive lock (empty = unlocked)

	// Config lock tracking: session ID of the holder (for auto-release on disconnect)
	configHolder string // unique session ID of the config lock holder
	// reclaimedHolders records the sessions whose lock reclaimStaleLockLocked
	// took on the idle lease (#9632). ensureHolderLocked refuses them while the
	// lock has no recorded holder: that empty holder is the internal / local
	// EnterConfigure() path, and #5059 deliberately lets OTHER user sessions
	// edit it. The session that was reclaimed must not ride that pass straight
	// back into the candidate that replaced its own. A session leaves the set
	// when it re-enters configure. Bounded by reclaimedHoldersCap.
	reclaimedHolders map[string]struct{}
	configLockAt     time.Time // when the lock was acquired

	// holderEpoch advances on every config-lock ACQUISITION and RELEASE, so a
	// commit authorized for one holder can detect that the lock turned over
	// before it reached promotion (#6808). It is deliberately separate from
	// candidateGen, which tracks candidate CONTENT: a turnover can leave
	// content-consistent state (B enters and stages edits, bumping candidateGen
	// in ways A's in-flight commit re-reads consistently), and configLockAt is a
	// wall-clock stamp that cannot distinguish a still-held lock from a
	// released-and-retaken one. Only a counter keyed to acquisition can.
	holderEpoch uint64

	// Cluster read-only mode: secondary nodes reject config mutations
	clusterReadOnly bool

	// Cluster node ID for ${node} variable expansion in apply-groups.
	// -1 means non-cluster (use CompileConfig), >= 0 means use CompileConfigForNode.
	nodeID int

	// Edit path for hierarchical navigation (edit/top/up)
	editPath []string

	// Archival settings
	archiveDir string // local archive directory (empty = disabled)
	archiveMax int    // max archives to keep

	// archiveSeedDir is the archive dir for which the archiveSeq reseed scan
	// last SUCCEEDED (#6396 Codex MINOR 4). ensureArchiveSeededLocked scans a
	// dir only when it differs from this. #6404: the reseed retry is driven not
	// only by an explicit SetArchiveConfig call but by the archiving commit path
	// itself (edge 1), which re-scans before capturing its seq; and if that scan
	// is still failing the commit SKIPS its archive (the counter is unconfirmed)
	// rather than write a below-max seq rotation would prune. This marker is
	// CLEARED on every genuine scan failure (so a stale marker is never trusted
	// after navigating to a dir that fails to scan — A→failed-B→A re-scans A) and
	// on disable (SetArchiveConfig("") — so a disable→re-enable to the same dir
	// re-scans to pick up any on-disk max that advanced while archival was off,
	// edge 2). A nonexistent dir (first use) is recorded here as CONFIRMED-empty,
	// not a failure — seq 0 is correct and the write path creates the dir.
	archiveSeedDir string

	// archiveScanCh / archiveScanDir hold the result channel of a reseed
	// directory scan that has been LAUNCHED but whose result has not been
	// consumed yet (#6776). The scan itself is a readdir(2) — an
	// UNINTERRUPTIBLE syscall that no context or deadline can cancel — so
	// ensureArchiveSeededLocked runs it on a throwaway goroutine and waits only
	// archiveScanBudget for it, rather than blocking the global store mutex
	// (and, at boot, the whole daemon bring-up) for however long the filesystem
	// takes to answer. When the budget expires the goroutine is ABANDONED, not
	// cancelled: it keeps its buffered channel, eventually completes, and the
	// reference kept here lets the NEXT call pick that result up with a
	// non-blocking poll instead of launching a second scan. That is what bounds
	// the cost of a wedged archive filesystem to exactly one budget-length stall
	// per process rather than one per commit, and bounds the leaked goroutine
	// count to one per distinct dir. The abandoned goroutine never touches Store
	// state — it only sends on its buffered channel — so it needs no lock and
	// can race with nothing. Both fields are guarded by s.mu.
	archiveScanCh  chan archiveScanResult
	archiveScanDir string

	// archiveSeq is a monotonic counter appended to every archive filename
	// (#3441 H4, Codex MAJOR). The wall-clock timestamp alone is not a unique
	// key: two successive (mutex-serialized) commits can format the SAME
	// nanosecond under a coarse clock or an NTP step-back, and the later atomic
	// write would overwrite the earlier archive. The seq always advances, so
	// config-<ts>.<seq>.conf is unique even on an identical timestamp; the seq
	// (not the ts) is the retention/prune key rotateArchives uses (#5523
	// C179-060). It is a per-PROCESS counter that restarts at 0, so
	// SetArchiveConfig seeds it from the highest seq on disk at startup, making
	// it globally monotonic across restarts — otherwise a fresh process's
	// low-seq archives would be pruned in favor of a prior process's stale
	// high-seq ones.
	archiveSeq atomic.Uint64

	// archiveWG tracks the in-flight async auto-archive writer goroutines
	// (#5869). Each archiving commit Add(1)s before it launches the
	// fire-and-forget writer; QuiesceArchival Wait()s on it so a factory reset
	// can JOIN every writer that has already started before it erases the
	// archive directory. Without the join an untracked writer could resume
	// AFTER FactoryResetArchiveDir removed /var/lib/xpf/archive and recreate a
	// config-<ts>.<seq>.conf snapshot of the PRIOR tenant's full config text
	// (cleartext IKE PSKs, WireGuard keys, SNMP communities) — zeroize secret
	// residue on a re-tenanted device.
	archiveWG sync.WaitGroup

	// archiveFenced is set true by QuiesceArchival at the start of a factory
	// reset (#5869). Once set, no NEW archive writer is launched (the commit
	// launch guard reads it under s.mu, so the Add/Wait ordering is race-free)
	// and an already-launched writer that has not yet written no-ops instead of
	// recreating the archive the zeroize is about to erase. It is a one-way
	// latch for the terminal reset path; ResumeArchival clears it only on the
	// fail-closed recoverable-wipe path so a daemon that stays up keeps
	// archiving normally.
	archiveFenced atomic.Bool

	// rollbackPersistDegraded records that the most recent
	// saveRollbackFiles() failed to durably write a rollback slot or sync
	// the directory (#3441 L1). The commit itself still succeeds — the
	// canonical active config persisted via the #1799 persist-before-promote
	// path — but the text rollback history (loadRollbackHistory reads it at
	// boot, #1894) is now stale/lossy. Surfaced via RollbackHistoryDegraded()
	// and a journal entry so the loss is visible instead of warning-only.
	// Cleared by the next fully-successful saveRollbackFiles().
	rollbackPersistDegraded bool

	// appliedDigest is the digest of the active config TEXT that most recently
	// completed a full apply to the dataplane/kernel (#4957). It is written by
	// the daemon (MarkActiveApplied) ONLY after applyConfigLocked returns success
	// for the current active config — at boot, on a committed config, and after a
	// peer config-sync. It is INTENTIONALLY not reset by a bare promotion: SyncApply
	// (and Commit/Load) promote s.active BEFORE the apply runs and, under the #1799
	// degrade-not-fail doctrine, do NOT roll s.active back when the subsequent apply
	// FAILS. So a config can be the active tree yet never have converged on the
	// dataplane. handleConfigSync's active-text convergence shortcut therefore ANDs
	// ActiveApplied() with its active==incoming check: a promoted-but-unapplied
	// synced config is NOT treated as converged, so the config high-water does not
	// advance past it and the primary's same-generation re-push re-attempts the
	// apply instead of being swallowed as a duplicate (the #4957 fail-open). Because
	// the marker is keyed on the config text, a stale value can only make the
	// shortcut MORE conservative (one idempotent re-apply), never falsely converged.
	appliedDigest string
}

// New creates a new config store. It fails closed when the .configdb
// directory cannot be created (#1893): there is no file-only fallback
// backend — every persistence path (Load, writeActive, the #1799
// persist-retry goroutine) dereferences the DB, so constructing a Store
// without one would trade this precise boot-time error for a delayed
// nil-pointer panic on the first Load/Save/commit.
func New(filePath string) (*Store, error) {
	dbDir := filepath.Join(filepath.Dir(filePath), ".configdb")
	db, err := NewDB(dbDir)
	if err != nil {
		return nil, fmt.Errorf("config db %s unusable: %w (no file-only fallback exists; refusing to run without config persistence)", dbDir, err)
	}

	journalPath := filepath.Join(filepath.Dir(filePath), ".config.journal")

	return &Store{
		active:                 &config.ConfigTree{},
		history:                NewHistory(50),
		filePath:               filePath,
		db:                     db,
		journal:                journal.New(journalPath),
		nodeID:                 -1,
		persistMarkerCommitted: true,
	}, nil
}

// ConfigPath returns the absolute path of the primary config file this Store
// loads from and persists to — the daemon's `-config` path (New's filePath).
// Its DIRECTORY is the configuration ROOT that holds the on-disk state a factory
// reset must erase: the `.configdb` SSOT + master.key (built at
// filepath.Join(filepath.Dir(filePath), ".configdb")), the numbered text
// rollback slots (`<base>.N`), and the audit journal
// (filepath.Join(filepath.Dir(filePath), ".config.journal")). The grpcapi
// zeroize handler reads it so the wipe targets the ACTUAL configured root rather
// than a hardcoded /etc/xpf (#5280): a daemon started with
// `-config /srv/xpf/site.conf` must have /srv/xpf erased, not /etc/xpf. filePath
// is set once by New and never mutated, so this needs no lock. Empty only on a
// zero-value Store never constructed via New.
func (s *Store) ConfigPath() string {
	return s.filePath
}

// SetConfigDBWriterVersion sets the xpf build version stamped into the
// config-DB compatibility-envelope header on write (#1917 increment B).
// Call once at startup before any Commit/Save; the daemon's single init
// path is the only caller.
func (s *Store) SetConfigDBWriterVersion(v string) {
	s.db.SetWriterVersion(v)
}

// SetClusterReadOnly toggles cluster read-only mode. When enabled, config
// mutations (EnterConfigure, Commit, Load, Set, Delete) are rejected.
// Used to prevent config changes on secondary cluster nodes.
func (s *Store) SetClusterReadOnly(ro bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clusterReadOnly = ro
}

// ClusterReadOnly returns whether the store is in cluster read-only mode.
func (s *Store) ClusterReadOnly() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clusterReadOnly
}

// SetNodeID sets the cluster node ID for ${node} variable expansion in
// apply-groups. Use -1 (default) for non-cluster mode.
func (s *Store) SetNodeID(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodeID = id
}

// compileTree compiles a config tree using the appropriate method based on
// whether the store is in cluster mode (nodeID >= 0) or standalone.
//
// Order of operations (#1319): the typed-leaf SchemaValidate gate runs
// BEFORE compile, but against the same apply-groups-expanded view the
// compiler consumes. Running on the raw candidate tree would let invalid
// typed leaves inside `groups { ... }` bypass the gate while still reaching
// the compiler after expansion. We still validate at commit time rather
// than at `set` time so the candidate-edit flow stays permissive —
// operators can stage half-typed values without each `set` line being
// rejected — and `commit check` is the one place that fails loud on garbage
// like `transmit-rate asd`. The tolerant Load/SyncApply ingress goes through
// compileTreeLenient below, which downgrades the same gate to a warning
// (#1319 PR 2 boot safety). cfg is nil at this point because we haven't
// compiled yet; the typed-leaf validators shipped so far don't need it.
func (s *Store) compileTree(tree *config.ConfigTree) (*config.Config, error) {
	return compileTreeStrict(tree, s.nodeID)
}

// compileTreeStrict is the package-level strict commit-check pipeline
// (typed-leaf SchemaValidate gate on the apply-groups-expanded view,
// then strict compile). It backs both Store.compileTree (every
// operator-driven commit / commit-check) and CheckText (check.go —
// the #1879 `xpfd check-config` day-0 validation gate), so the two
// callers can never drift apart.
func compileTreeStrict(tree *config.ConfigTree, nodeID int) (*config.Config, error) {
	if err := schemaValidateExpandedTreeForNode(tree, nodeID); err != nil {
		return nil, err
	}
	var compiled *config.Config
	var err error
	if nodeID >= 0 {
		compiled, err = config.CompileConfigForNode(tree, nodeID)
	} else {
		compiled, err = config.CompileConfig(tree)
	}
	if err != nil {
		return nil, err
	}
	if err := crossCheckNodeID(compiled, nodeID); err != nil {
		return nil, err
	}
	if err := crossCheckRAIntervals(compiled); err != nil {
		return nil, err
	}
	// #5876 + #4785: a chassis-cluster commit must adjudicate the REGISTERED
	// peer-effective concerns on BOTH node-effective views before promotion, not
	// only the submitting node's. "The registered concerns", because the registry
	// holds exactly two subjects (source NAT and the emitted-IPIP endpoint), and
	// the registry on its own is conditional on the peer view COMPILING — a peer
	// view that does not compile is left unadjudicated by
	// ValidatePeerEffectiveStrict (see the #6861 F2 paragraph further down for
	// the case where that swallow bit). #9619 closes both limits at this call
	// site: validatePeerStrictPipeline, after the registry, runs every strict
	// step of this function on the peer's view, so neither an unregistered gate
	// nor an uncompilable peer view passes a shared commit.
	// This gate compiles for the local node alone (CompileConfigForNode above),
	// so a ${node} apply-group substitution / per-node rewrite that selects a
	// source-NAT pool valid on the origin but invalid on the peer — or a
	// peer-only `ip-*` interface whose inferred `mode ipip` the dataplane drops
	// in both directions — passes green. What synchronises is the RAW group
	// tree, and the standby ingests it leniently (Store.SyncApply), so the
	// defect installs on the peer with no strict check anywhere. Re-run the
	// registered strict subjects against the peer's effective compile (the same
	// CompileConfigForNodeLenient transform the standby applies) so a peer-only
	// error is rejected here, at the one strict gate that ever sees this config.
	// Standalone (nodeID < 0) has no peer and is a no-op.
	//
	// #6861 F2: the gate must be handed the tree the PEER will actually
	// compile, not the raw candidate. Store.SyncApply runs
	// rewriteRetiredDataplaneType BEFORE compileTreeLenient, so a peer
	// `groups nodeN` block carrying a retired `system dataplane-type` leaf
	// compiles fine on the standby but fails the unconditional retirement
	// validator here. ValidatePeerEffectiveStrict treats a peer view that
	// will not compile as out of scope and returns nil — so the gate
	// returned SUCCESS WITHOUT EVER RUNNING ITS IPIP SUBJECT, and the
	// standby then stripped the retired leaf and installed the dead tunnel.
	// Reproduced end-to-end before this fix: node0 committed green, node1's
	// SyncApply installed `ip-0/0/0` mode ipip.
	//
	// The rewrite is applied to a CLONE. Mutating the candidate here would
	// silently strip the operator's own leaf out of the tree being
	// committed — the strict local path must keep rejecting it, and the
	// peer group's leaf must survive to sync so the standby's own
	// tolerance is what handles it.
	peerTree := tree.Clone()
	rewriteRetiredDataplaneType(peerTree, SyncCaller)
	if err := config.ValidatePeerEffectiveStrict(peerTree, nodeID); err != nil {
		return nil, err
	}
	// #9619: the registry above runs FIRST so its two subjects keep their
	// specific messages; this then runs the whole strict pipeline on the same
	// rewritten peer tree, which covers every other strict gate and also the
	// peer view that does not compile at all (the registry's skip arm).
	if err := validatePeerStrictPipeline(peerTree, nodeID); err != nil {
		return nil, err
	}
	return compiled, nil
}

// crossCheckNodeID rejects a config whose compiled `chassis cluster node`
// leaf disagrees with the effective node identity (#4185). nodeID is the
// SSOT node identity: the /etc/xpf/node-id file value on an operator commit
// (Store.compileTree passes s.nodeID) or the `-node-id` flag on
// `xpfd check-config` (CheckText). The file drives ${node} apply-group
// expansion + boot class; the leaf drives FPC naming + heartbeat identity —
// a divergence yields two half-identities (node 0's per-node IPs duplicated
// on the wire) with no diagnostic. We reject the commit/check while the
// operator can still fix it rather than let it boot half-standalone.
//
// This runs ONLY on the strict commit/commit-check path (compileTreeStrict).
// The tolerant Store.Load / Store.SyncApply ingress uses compileTreeLenient,
// which is deliberately NOT cross-checked: a config-sync push carries the
// primary's expanded text, and the standby re-expands ${node} for its own
// node, so the leaf already agrees with the standby's file after expansion —
// and even a legacy/laxly-authored synced config must not blackout-boot the
// standby (same doctrine as the #1319/#1798 lenient gates).
//
// Standalone (nodeID < 0) and configs without an explicit node leaf
// (NodeIDSet false) never cross-check — an absent leaf on a node-1 box must
// not false-reject as "node 0".
func crossCheckNodeID(compiled *config.Config, nodeID int) error {
	if compiled == nil || nodeID < 0 {
		return nil
	}
	cc := compiled.Chassis.Cluster
	if cc == nil || !cc.NodeIDSet {
		return nil
	}
	if cc.NodeID != nodeID {
		return fmt.Errorf("node identity mismatch: the node-id file / -node-id is %d but "+
			"'chassis cluster node' resolves to %d after ${node} expansion — these MUST agree "+
			"(the file drives ${node} apply-group expansion and boot class; the leaf drives FPC "+
			"naming and heartbeat identity). Fix one so both name the same node", nodeID, cc.NodeID)
	}
	return nil
}

// crossCheckRAIntervals enforces the one RFC 4861 §6.2.1 constraint the
// per-leaf schema validators cannot express: when a router-advertisement
// interface configures BOTH min- and max-advertisement-interval,
// MinRtrAdvInterval MUST be <= 0.75 * MaxRtrAdvInterval (#4525). The
// per-leaf gate (schema_routing.go) already bounds each leaf on its own —
// max in [4,1800], min in [3,1350] per RFC 4861 §6.2.1 — but only the
// compiled view sees both siblings together, so the ratio check lives here
// (mirroring crossCheckNodeID's strict-only placement). An inverted or
// over-narrowed window (min > 0.75*max) is the config that motivated #4525:
// max-advertisement-interval 1|2 let the sender draw a 0-second periodic
// delay and hot-loop; even within the new per-leaf floors an operator could
// still author min close to max, which RFC 4861 forbids because it defeats
// the desynchronizing jitter.
//
// Absent leaves (value 0 = "use default") never cross-check: a lone max or a
// lone min is completed by the RA sender's own derivation (pkg/ra
// randomAdvInterval), which is safe. Only an explicit min > 0.75*max pairing
// is rejected.
//
// Strict on the operator commit / commit-check path (compileTreeStrict);
// downgraded to a warning on the tolerant Store.Load / Store.SyncApply
// ingress (compileTreeLenient) so a legacy or peer-synced config cannot
// blackout-boot the node or alarm-loop HA config sync (#1960 doctrine). The
// runtime floor in pkg/ra randomAdvInterval is the belt for anything that
// reaches the sender through the lenient path.
func crossCheckRAIntervals(compiled *config.Config) error {
	if compiled == nil {
		return nil
	}
	for _, ra := range compiled.Protocols.RouterAdvertisement {
		if ra == nil || ra.MinAdvInterval <= 0 || ra.MaxAdvInterval <= 0 {
			continue
		}
		// Integer form of min <= 0.75 * max (avoids float rounding):
		// min*4 <= max*3.
		if ra.MinAdvInterval*4 > ra.MaxAdvInterval*3 {
			return fmt.Errorf("router-advertisement interface %q: min-advertisement-interval "+
				"%d must be <= 0.75 * max-advertisement-interval %d per RFC 4861 §6.2.1 — "+
				"lower min-advertisement-interval or raise max-advertisement-interval",
				ra.Interface, ra.MinAdvInterval, ra.MaxAdvInterval)
		}
	}
	return nil
}

// compileTreeLenient is compileTree with the tolerant-path validator
// downgrades enabled (config.CompileConfigLenient /
// CompileConfigForNodeLenient: #1798 control-char sanitize, lenient
// VRRP track duplicates). It is used ONLY by the passive load
// (Store.Load) and HA peer-sync (Store.SyncApply) ingress paths, and by
// RetainedGeneration (#9641) to recompile a retained tree that one of those
// paths or a commit already accepted, NOT by any operator-driven candidate
// commit / commit-check path.
//
// Rationale: Store.Load and Store.SyncApply compile a config the operator
// did NOT just author — a persisted active config on local boot, or a
// config pushed from a possibly-un-upgraded cluster primary. A strict
// reject here would (a) fail Store.Load on an upgraded node carrying a
// legacy config, leaving the daemon with no active config (operational
// blackout), and (b) fail Store.SyncApply on an upgraded standby
// receiving such a config from an un-upgraded primary, alarm-looping HA
// config sync. The operator's next strict candidate commit rejects it.
//
// (The original #1733 equal-flow worker-cap downgrade that motivated
// this split was retired in #1830 (e) — the dataplane no longer caps
// equal-flow-enforcement at 32 workers.)
func (s *Store) compileTreeLenient(tree *config.ConfigTree) (*config.Config, error) {
	// #1319 PR 2: the typed-leaf SchemaValidate gate is STRICT only on the
	// operator-driven commit / commit-check path (compileTree). Here — the
	// tolerant Store.Load / Store.SyncApply ingress for configs the
	// operator did NOT just author — a violation downgrades to a warning.
	// A persisted config written by an older binary (pre-gate, or before a
	// leaf's range was typed/tightened) may carry values the current gate
	// rejects; hard-failing would blackout-boot the node (Load) or
	// alarm-loop HA config sync (SyncApply), even though the compiler
	// accepted the value when it was committed and still compiles it the
	// same way today. This is the same doctrine as the #1733/#1798/#1814
	// lenient compile gates (see freetext.go); the operator's next strict
	// commit rejects the stale value loudly.
	if err := s.schemaValidateExpandedTree(tree); err != nil {
		slog.Warn("typed-leaf schema violation in tolerated config; continuing (a strict commit would reject this)",
			"err", err, "issue", "#1319")
	}
	var compiled *config.Config
	var err error
	if s.nodeID >= 0 {
		compiled, err = config.CompileConfigForNodeLenient(tree, s.nodeID)
	} else {
		compiled, err = config.CompileConfigLenient(tree)
	}
	// #4185 (review Finding 2): the lenient Load/SyncApply path must NOT
	// hard-reject a node-id mismatch (that would blackout-boot the node or
	// alarm-loop HA config sync — the #1960 doctrine), but a silent literal
	// `chassis cluster node` leaf that disagrees with this node's identity
	// (e.g. leaf 0 reaching a node-1 box via config-sync) causes a heartbeat-id
	// collision + wrong FPC naming with no diagnostic. Warn (non-fatal) so the
	// observability hole is closed without bricking the standby. The operator's
	// next strict commit rejects it outright (crossCheckNodeID).
	if err == nil {
		if mismatch := crossCheckNodeID(compiled, s.nodeID); mismatch != nil {
			slog.Warn("node identity mismatch in tolerated config; continuing (a strict commit would "+
				"reject this) — heartbeat identity and FPC naming may diverge from ${node} expansion",
				"err", mismatch, "issue", "#4185")
		}
		if raErr := crossCheckRAIntervals(compiled); raErr != nil {
			slog.Warn("router-advertisement interval violation in tolerated config; continuing "+
				"(a strict commit would reject this) — the RA sender floors the periodic timer at 1s",
				"err", raErr, "issue", "#4525")
		}
	}
	return compiled, err
}

func (s *Store) schemaValidateExpandedTree(tree *config.ConfigTree) error {
	return schemaValidateExpandedTreeForNode(tree, s.nodeID)
}

func schemaValidateExpandedTreeForNode(tree *config.ConfigTree, nodeID int) error {
	if tree == nil {
		return nil
	}
	// #2008 H1: strip `inactive:` subtrees BEFORE group expansion so the
	// schema/check path agrees with the compile path (strip -> expand ->
	// validate; see compileConfigWithOpts in compiler.go). ExpandGroups
	// (ast_groups.go) collects every `apply-groups` node by name WITHOUT
	// checking Inactive, so without this an `inactive: apply-groups foo`
	// would still expand group foo (false-validating inherited content the
	// compiler will never apply) and an `inactive: apply-groups missing`
	// would still fail commit-check as an undefined group. Stripping here —
	// not only inside SchemaValidateWithDefinitions, which runs AFTER
	// expansion — makes the marker actually deactivate group inheritance.
	// WithoutInactive is a no-op (no clone) on the all-active path; the
	// stripped, normalized PRE-EXPANSION tree is passed as defsSource so a
	// definition living only in an un-applied peer-node group keeps
	// satisfying shared-section references (#1319 PR 3), and is collected in
	// whichever spelling it was authored (#8921).
	// #8921: normalize brace-elided statements BEFORE expansion and AFTER
	// stripping inactive nodes -- the order the compile path uses
	// (compileConfigWithOpts: strip -> normalize -> expand). ExpandGroups merges a group body into inline config by the
	// statement's SHAPE, so a group spelling `neighbor 192.0.2.1 hold-time 2;`
	// packed failed to meet an inline `neighbor 192.0.2.1 { hold-time 30; }`,
	// was appended beside it instead of being overridden, and was then
	// normalized and REFUSED as an invalid hold-time -- while the braced group
	// body merged, the override won, and the same config validated clean. The
	// compiler, which already normalized first, accepted both, so commit-check
	// and compile disagreed about one config. The definitions source is
	// normalized for the same reason: collectSchemaRefs reads definitions by
	// shape too. NormalizeCompactForScan clones before rewriting, so the
	// caller's tree is untouched.
	//
	// STRIP FIRST, and it is not cosmetic: the fold declines when the NEXT
	// sibling continues the container it would build (#8880), so an inactive
	// sibling the compiler never sees -- `neighbor 192.0.2.1 hold-time 30;
	// inactive: hold-time 9;` -- made commit-check decline a fold the compiler
	// performs, and the same override failed to merge again.
	stripped := config.NormalizeCompactForScan(tree.WithoutInactive())
	expanded := stripped.Clone()
	if nodeID >= 0 {
		vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
		if err := expanded.ExpandGroupsWithVars(vars); err != nil {
			return fmt.Errorf("apply-groups: %w", err)
		}
		// Pass the PRE-expansion candidate as the cross-reference
		// definitions source: expansion removes the groups stanza, and
		// definitions living only in un-applied peer-node groups must
		// keep satisfying shared-section references (#1319 PR 3).
		return config.SchemaValidateWithDefinitions(expanded, stripped, nil)
	}
	if err := expanded.ExpandGroups(); err != nil {
		if strings.Contains(err.Error(), `undefined group "${node}"`) {
			vars := map[string]string{"node": "node0"}
			if err2 := expanded.ExpandGroupsWithVars(vars); err2 != nil {
				return fmt.Errorf("apply-groups: %w", err2)
			}
		} else {
			return fmt.Errorf("apply-groups: %w", err)
		}
	}
	return config.SchemaValidateWithDefinitions(expanded, stripped, nil)
}

// SyncApply applies a config received from the cluster primary.
// Bypasses cluster read-only checks. The chassisPreserve function, if set,
// lets the caller patch the parsed tree before compiling (e.g. to preserve
// local chassis cluster settings).
func (s *Store) SyncApply(content string, chassisPreserve func(*config.ConfigTree)) (*config.Config, error) {
	// H-2: the HA peer config-sync ingress is a network-reachable parse entry
	// point (a hostile/corrupt peer config over the fabric). Reject an
	// over-large payload before parsing so one bad peer cannot crash the
	// standby.
	if err := checkConfigSize(content); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tree, errs := config.NewParser(content).Parse()
	if len(errs) > 0 {
		return nil, fmt.Errorf("sync config parse error: %v", errs[0])
	}

	// Let caller patch the tree (e.g. preserve local chassis cluster settings).
	if chassisPreserve != nil {
		chassisPreserve(tree)
	}

	// Rolling-upgrade tolerance (AGY r4 finding on #1476): an
	// un-upgraded primary may push a config that still selects
	// the retired DPDK or eBPF dataplane. Strict-validator-driven
	// sync rejection would alarm-loop the cluster. Rewrite the
	// retired leaf so the standby boots through cleanly while the
	// operator updates the primary.
	rewriteRetiredDataplaneType(tree, SyncCaller)

	// #1798 migration: same tolerance as Load — a peer-synced config
	// from a possibly-un-upgraded primary may carry control characters
	// in free-text values. Scrub the tree in place with a warning so
	// HA config sync does not alarm-loop and the standby's stored tree
	// stays clean for any later strict commit.
	for _, p := range config.SanitizeTreeControlChars(tree) {
		slog.Warn("sanitized control characters in peer-synced config value",
			"path", p, "issue", "#1798")
	}

	// Tolerant compile: a config peer-synced from a possibly-un-upgraded
	// primary must not alarm-loop HA sync (see compileTreeLenient for
	// the validator downgrades).
	compiled, err := s.compileTreeLenient(tree)
	if err != nil {
		return nil, fmt.Errorf("sync config compile error: %w", err)
	}

	// Push current active to history.
	s.history.Push(&HistoryEntry{
		Config:    s.active.Clone(),
		Timestamp: time.Now(),
	})

	s.active = tree
	s.compiled = compiled
	s.dirty = false

	// If in config mode, update candidate too.
	if s.configDir {
		s.candidate = s.active.Clone()
		s.bumpCandidateGenLocked() // #5848: candidate reset by authoritative load/sync
	}

	// #3861: an authoritative config synced from the cluster primary
	// supersedes any commit-confirmed window still pending on THIS node
	// (e.g. a node that armed `commit confirmed`, failed over to standby,
	// then received a sync from the new primary). The pending timer's
	// rollback target is the local pre-confirm tree — now stale; letting
	// it fire would silently revert this node to a pre-sync config and
	// diverge it from the cluster. Treat the sync as the confirmation:
	// cancel the timer and bump confirmGen so an already-fired-but-blocked
	// callback no-ops in PromoteRollback. This runs with the in-memory
	// promotion (Option B: the apply stands even if the disk write below
	// fails), matching SyncApply's degrade-not-fail contract.
	//
	// #5473: cancel the timer here but DO NOT remove confirm.json yet — order
	// its removal AFTER the writeActive below so the crash-recovery record is
	// dropped only once the synced (replacement) config is durable. If the
	// degrade-not-fail write fails and we had removed confirm.json up front, a
	// crash before the retry heals would boot the pre-sync config with no
	// record; the re-armed rollback would then be lost. cancelPending returns
	// true iff a window was actually pending, so confirm.json is touched only
	// when there was one to resolve.
	syncSupersededConfirm := s.cancelPendingConfirmTimerLocked()
	if syncSupersededConfirm {
		slog.Info("HA config-sync apply confirmed a pending commit-confirmed window")
	}

	// #1799 Option B (degrade-not-fail): the in-memory apply above
	// MUST stand even if the disk write fails — failing the
	// secondary's apply on local disk trouble would silently diverge
	// the cluster (sync is one-way fire-and-forget; the primary is
	// already running the new config and is never notified). The
	// failure becomes visible (degraded flag → /health 503 +
	// Prometheus gauge + journal ERROR) and self-healing (singleton
	// background retry with backoff).
	//
	// #1922 step-0: a successful config sync from the primary counts as a
	// commit for the never-vs-empty disambiguation — a synced secondary has
	// an authoritative config and must never read as never-committed. Set
	// the markers BEFORE the persist so a failed-then-healed write (the
	// retry loop) also stamps committed=1.
	s.everCommitted = true
	s.persistMarkerCommitted = true
	if err := s.writeActive(s.active); err != nil {
		s.noteActivePersistFailureLocked("config_sync", err)
		// #5473: the synced config that supersedes the pending confirm window
		// is NOT durable. Keep confirm.json and defer its removal until the
		// retry lands the synced config durably — a crash before then boots
		// into a state where the persisted rollback still fires.
		if syncSupersededConfirm {
			s.confirmResolvePendingPersist = true
		}
	} else {
		s.persistDegraded = false
		// The synced config is durable. Drop the confirm.json this sync
		// superseded now that the replacement is on disk.
		if syncSupersededConfirm {
			// #5835: a failed removal retains retry debt + degraded health
			// rather than being swallowed.
			s.resolveConfirmRemovalLocked("config_sync_remove")
		}
		// Also finalize any removal deferred by an EARLIER failed resolution
		// write (e.g. a prior rollback whose persist failed): the synced config
		// is durable, so that stale window is definitively superseded too.
		// No-op unless such a removal was pending.
		s.clearConfirmResolutionPendingLocked()
	}

	s.journalLog(&JournalEntry{
		Action:     "config_sync",
		ConfigHash: journalConfigHash(s.active),
	})

	s.saveRollbackFiles()
	return compiled, nil
}

// configTextDigest returns a stable hex digest of a rendered config's text,
// whitespace-normalized so it matches the ShowActive()/incoming-text comparison
// handleConfigSync already performs (both sides are the canonical hierarchical
// render a primary pushes via ShowActive).
func configTextDigest(text string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(text)))
	return hex.EncodeToString(sum[:])
}

// MarkActiveApplied records that the CURRENT active config has completed a full
// apply to the dataplane/kernel (#4957). The daemon calls it after a successful
// applyConfigLocked for the active config — the boot apply, a committed config,
// and a peer config-sync. It stamps the digest of the active text so a later
// ActiveApplied() can tell whether the tree that is active NOW is the one that
// converged. A no-op is safe if active is nil (nothing to have applied).
func (s *Store) MarkActiveApplied() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		s.appliedDigest = ""
		return
	}
	s.appliedDigest = configTextDigest(s.active.Format())
}

// ActiveApplied reports whether the CURRENT active config is the one that most
// recently completed a full apply (#4957). It is FALSE in the window after active
// has been promoted (SyncApply/Commit/Load) but before the subsequent apply
// succeeds — including the #4957 case where a peer-synced config was promoted to
// active but its apply FAILED and was never rolled back (degrade-not-fail). A nil
// active, or a never-applied store, reads as not-applied.
func (s *Store) ActiveApplied() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active == nil || s.appliedDigest == "" {
		return false
	}
	return s.appliedDigest == configTextDigest(s.active.Format())
}

// ActiveDigest returns the convergence digest of the CURRENT active config
// text — exactly the value ActiveApplied() compares appliedDigest against
// (configTextDigest(s.active.Format()), the ShowActive render). It lets a
// caller CAPTURE the digest of the config it is about to apply, under its own
// apply serialization, and stamp that captured value later via
// MarkAppliedDigest — instead of re-reading s.active at stamp time. A concurrent
// promoter (a local commit / commit-confirmed rollback) that mutated s.active
// between the apply and a post-serialization stamp would otherwise make
// MarkActiveApplied key the marker to a different, never-applied tree (the #6296
// TOCTOU). Empty when active is nil (nothing to have applied).
func (s *Store) ActiveDigest() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active == nil {
		return ""
	}
	return configTextDigest(s.active.Format())
}

// MarkAppliedDigest records that the config whose convergence digest is
// `digest` has completed a full apply to the dataplane/kernel (#6296). Unlike
// MarkActiveApplied — which re-reads s.active at call time — it stamps a digest
// the caller captured earlier (via ActiveDigest) for the exact tree it applied.
// So a stamp taken after the apply serialization is released, or one racing a
// concurrent promoter that mutated s.active in that window, cannot key the
// marker to a different, never-applied tree. The cluster config-sync path
// (daemon.syncAndApply) captures the digest right after SyncApply promotes the
// peer config — while still holding the apply semaphore — and replays it here on
// full success. An empty digest is a no-op (nothing was captured / applied); it
// deliberately does NOT clear a prior digest.
func (s *Store) MarkAppliedDigest(digest string) {
	if digest == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appliedDigest = digest
}

// InvalidateAppliedDigest clears the applied marker because an apply FAILED
// (#9175). It is the missing counterpart to the two stamps above: they were the
// only writers, so the digest recorded a success and nothing ever unrecorded it.
//
// Why "keyed on the config text" was not enough. A promotion moves the active
// text away from a stale digest, so in a FORWARD sequence the marker can only be
// over-conservative — which is what the field comment claimed and what #4957
// relied on. Re-promotion breaks that: if A applied, B was promoted and failed,
// and A is promoted again and ALSO fails, the digest from A's original success
// still matches the active text and `ActiveApplied()` reports converged for a
// dataplane that never took the config.
//
// The invalidation is deliberately UNCONDITIONAL rather than conditioned on the
// failing config being the stamped one. Deciding "which text failed" needs a
// digest the failing path does not always hold (a context abort bails before any
// capture), and being wrong in THAT direction is exactly the falsely-converged
// state this exists to prevent. Being wrong in the other direction costs one
// idempotent re-apply — the same cost the #4957 shortcut avoids, and the correct
// side to be wrong on.
//
// Called from `applyConfigLocked`'s error path, the single choke point every
// apply in the daemon goes through. Putting it there rather than at each
// caller's failure branch is what keeps a future apply site from silently
// inheriting the defect.
func (s *Store) InvalidateAppliedDigest() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appliedDigest = ""
}
