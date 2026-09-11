// Package dhcpserver manages Kea DHCP server configuration and lifecycle.
package dhcpserver

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// systemctlTimeout bounds every systemctl shell-out. Apply/Clear run on
// the config-apply path under applyConfigLocked's applySem
// (daemon_apply.go d.dhcpServer.Apply), so a hung systemctl (dbus
// stall, wedged Kea stop job) would otherwise block every commit
// indefinitely. Mirrors the 15s FRR reload precedent
// (pkg/frr/manager.go reloadTimeout). #1794/#1800.
const systemctlTimeout = 15 * time.Second

// runSystemctl runs `systemctl <args...>` under systemctlTimeout. On
// failure the returned error includes the captured output, so callers
// that previously logged a bare exit status now surface the systemd
// diagnostic too.
func runSystemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	// WaitDelay caps the post-SIGKILL pipe-drain window.
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// unitIsActive reports whether a systemd unit is active (or on its way
// up) by querying `systemctl is-active`. It returns (active, err):
//
//   - A recognized state string on stdout is an authoritative answer,
//     regardless of exit code. `systemctl is-active` exits non-zero for
//     an inactive/failed/unknown unit but still prints the state, so
//     that expected ExitError is NOT a query failure — active is
//     reported (true/false) with a nil error.
//   - No recognized state string (empty/garbled output, a missing
//     systemctl binary, a context timeout/kill) means the query could
//     NOT determine the unit's state. That is returned as a non-nil
//     error so callers fail CLOSED (#4870) instead of silently mapping
//     the uncertainty to "inactive" — which let a transient is-active
//     failure skip a restart/stop and report the commit as successful
//     while stale/removed Kea policy kept being served.
func unitIsActive(unit string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", unit)
	cmd.WaitDelay = 5 * time.Second
	out, runErr := cmd.Output()
	state := strings.TrimSpace(string(out))
	switch state {
	case "active", "activating", "reloading", "deactivating":
		// "deactivating" counts as active-for-stop (Codex review on PR
		// #1835): a previous daemon or external restart job can be
		// mid-stop with a queued start behind it — skipping the stop
		// here would let that queued start resurrect Kea after this
		// commit removed its config. An extra stop on a unit that was
		// going down anyway is harmless.
		return true, nil
	case "inactive", "failed", "unknown", "maintenance":
		// A definitive not-active answer. `systemctl is-active` prints
		// these to stdout and exits non-zero, so runErr here is the
		// expected ExitError, not a query failure — discard it.
		return false, nil
	}
	// No recognized state: the query itself failed. Surface the reason
	// so the caller can fail closed rather than assume "inactive".
	if runErr == nil {
		runErr = fmt.Errorf("unrecognized output %q", state)
	}
	return false, fmt.Errorf("systemctl is-active %s: %w", unit, runErr)
}

const (
	// DefaultKea4ConfPath / DefaultKea6ConfPath are the Kea server config files
	// xpf renders. Exported so a factory-reset zeroize can erase them directly
	// (#4585) — xpf owns these whole files, so a wipe removes them outright.
	DefaultKea4ConfPath = "/etc/kea/kea-dhcp4.conf"
	DefaultKea6ConfPath = "/etc/kea/kea-dhcp6.conf"

	kea4Config = DefaultKea4ConfPath
	kea6Config = DefaultKea6ConfPath
	kea4Svc    = "kea-dhcp4-server"
	kea6Svc    = "kea-dhcp6-server"
	// Kea memfile lease databases (per family). Shared by the display
	// reader, the DDNS reconciler, and the #2239 lease-sync memfile
	// fallback so the path is defined once.
	keaLeaseFile4 = "/var/lib/kea/kea-leases4.csv"
	keaLeaseFile6 = "/var/lib/kea/kea-leases6.csv"
)

// libDHCPLeaseCmdsPath is the absolute path of the lease_cmds hook library.
// The #2239 lease-sync read/seed path issues lease{4,6}-get-all and
// lease{4,6}-add over the control socket; both require this hook loaded in the
// generated Kea config. It ships in kea-common (live-verified 3.0.3), so no new
// apt package is needed; if the file is ever absent the read path falls back to
// the memfile parser.
const libDHCPLeaseCmdsPath = "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so"

// Manager manages Kea DHCP server processes.
//
// The manager is authoritative over the kea-dhcp{4,6}-server units
// (#1778): it reconciles against the ACTUAL systemd unit state
// (`systemctl is-active`) rather than process-local booleans, so a
// stale Kea left running by a previous xpfd instance is stopped when
// the current config has no matching dhcp-server stanza.
type Manager struct {
	mu        sync.Mutex
	confPath4 string
	confPath6 string

	// Seams for tests (see test_seams.go). Production instances get
	// the package-level implementations from New().
	runSystemctl func(args ...string) error
	unitActive   func(unit string) (bool, error)
	warn         func(msg string, args ...any)

	// Generation-ordered supersession (#1835 F2 redesign after the
	// Codex confirm on PR #1835 head dcd98cf8e). EVERY applier — sync
	// Apply, sync ApplyClusterCommit, and ApplyAsync — allocates a
	// monotonic generation at CALL ENTRY from applyGen. The shared
	// apply body skips any request whose gen is <= lastAppliedGen
	// (a newer desired state already won), so a queued async request
	// can never be applied over a later synchronous commit and vice
	// versa: allocation order == arrival order, and the final state
	// is always the newest caller's.
	applyGen atomic.Uint64
	// lastAppliedGen is the generation of the newest desired state
	// whose apply body ran (guarded by mu). Set even when the apply
	// errored: the newest state was ATTEMPTED, and replaying an older
	// state over a failed newer one would regress desired state.
	lastAppliedGen uint64
	// shuttingDown latches at daemon shutdown (#6787). Once set, EVERY
	// applier — sync Apply, ApplyClusterCommit, and the async worker —
	// coerces its desired state to nil, so no late caller can restart Kea
	// after the node has begun relinquishing ownership.
	//
	// A latch rather than a second stop call, because the hazard is a race,
	// not a missed step: `Shutdown` runs BEFORE the priority-0 withdrawal so
	// this node stops serving before the peer starts, which leaves a window in
	// which a VRRP MASTER transition can still enqueue an ApplyAsync with a
	// HIGHER generation and re-arm the units. The supersession guard cannot
	// help there — the racing request is genuinely newer. Coercing rather than
	// REFUSING keeps the reconcile idempotent and convergent: a late applier
	// still runs, and still lands on "stopped".
	shuttingDown atomic.Bool
	// staleApplySkips counts apply bodies skipped as superseded
	// (observable by tests; useful telemetry if exported later).
	staleApplySkips atomic.Uint64

	// applyFailed records whether the most recently COMPLETED apply
	// attempt returned an error. #6535: in cluster mode the only trigger
	// for a Kea apply is the RG-transition EDGE (applyRethServicesForRG /
	// clearRethServicesForRG, both gated on tr.Changed) or an operator
	// commit — there is no periodic converger — so a failed apply is
	// simply lost. The node that should be serving stays dark, or the node
	// that should have stopped keeps serving, until the next transition or
	// commit: persistent dual-DHCP (or no-DHCP) after a failover. This flag
	// is the debt a converger can consume; it is advanced ONLY on a
	// completed attempt and cleared only by a successful one.
	//
	// A SUPERSEDED apply (gen <= lastAppliedGen) deliberately leaves it
	// alone: that request never ran, and the newer state that displaced it
	// owns the outcome.
	//
	// Guarded by retryMu, NOT mu. mu is held for the whole apply body,
	// which shells out to systemctl under a 15 s bound; a converger
	// running on the daemon's 2 s reconcile tick must be able to ask
	// "did the last attempt fail?" without blocking behind a restart
	// that is still running. Lock order is mu -> retryMu (only the tail
	// of apply takes both); ClaimApplyRetry takes retryMu alone.
	applyFailed bool
	// lastRetryClaim is when a converger last CLAIMED a retry, used to
	// space out retries. Kea applies shell out to systemctl with a 15 s
	// bound, so a permanently broken Kea must not be re-driven on every
	// 2 s reconcile tick. Guarded by retryMu.
	lastRetryClaim time.Time
	retryMu        sync.Mutex

	// ApplyAsync mailbox (#1835 F2): a mutex-guarded 1-slot pending
	// pointer plus a cap-1 wake channel, consumed by a single lazily
	// started worker goroutine, so VRRP transition callbacks never
	// block behind a 15s systemctl. (The first design used a cap-1
	// data channel with a send-after-drain retry loop; Codex showed
	// that loop is ABA-racy — an old producer could drain a newer
	// producer's request and land its older one. The pending slot is
	// overwritten only by a higher gen, so it is monotonic.)
	asyncOnce    sync.Once
	asyncMu      sync.Mutex
	pendingAsync *asyncApplyReq
	asyncNotify  chan struct{}
	// asyncWorkerStarts counts worker goroutine launches; tests assert
	// the sync.Once keeps it at 1 across ApplyAsync bursts.
	asyncWorkerStarts atomic.Int32

	// #2239 HA DHCP-server lease synchronization (PATH C). When
	// leaseSyncEnabled is set (cluster + `dhcp-lease-synchronization`
	// knob), the generated Kea config gains a unix control-socket and the
	// lease_cmds hook so leases can be read (lease{4,6}-get-all) and seeded
	// (lease{4,6}-add) without racing the memfile. The flag is set by the
	// daemon via SetLeaseSyncEnabled before an apply; standalone / knob-off
	// leaves the config bit-identical to pre-#2239.
	leaseSyncEnabled atomic.Bool

	// keaDial / ctrlSocket{4,6} / leaseFile{4,6} are test seams for the
	// lease-sync read/seed path (lease_sync.go). Production leaves them
	// zero, which selects net.Dial + the package-default paths.
	keaDial     keaSocketDialer
	ctrlSocket4 string
	ctrlSocket6 string
	leaseFile4  string
	leaseFile6  string

	// Kea runtime-user resolution for the memfile pre-seed (#2450). The
	// pre-seeded lease memfile must be chowned to the unprivileged Kea user
	// (_kea / kea) so Kea can open it RW on takeover; otherwise it fails to
	// start (EACCES) and DHCP goes dark. keaOwnerLookup is a test seam (nil
	// selects the real os/user lookup); the resolution is cached behind
	// keaOwnerOnce so the takeover path does not read /etc/passwd per
	// pre-seed.
	keaOwnerOnce   sync.Once
	keaOwnerLookup func() (uid, gid int, ok bool)
	keaOwnerUID    int
	keaOwnerGID    int
	keaOwnerOK     bool
}

// SetLeaseSyncEnabled toggles emission of the Kea control-socket + lease_cmds
// hook in the generated config (#2239). It takes effect on the next apply; the
// daemon calls it from the config-apply path when the cluster
// `dhcp-lease-synchronization` knob is set.
func (m *Manager) SetLeaseSyncEnabled(enabled bool) {
	m.leaseSyncEnabled.Store(enabled)
}

// asyncApplyReq is one desired DHCP-server state for the ApplyAsync
// worker. gen orders it against every other applier (sync and async);
// reason is logging context only (which VRRP transition asked).
type asyncApplyReq struct {
	gen    uint64
	cfg    *config.DHCPServerConfig
	reason string
}

// New creates a new DHCP server manager.
func New() *Manager {
	return &Manager{
		confPath4:    kea4Config,
		confPath6:    kea6Config,
		runSystemctl: runSystemctl,
		unitActive:   unitIsActive,
		warn:         slog.Warn,
	}
}

// Apply reconciles the Kea DHCP servers with the xpf DHCP server
// config. For each address family that is configured it regenerates
// the Kea config and restarts the unit; for each family that is NOT
// configured (including cfg == nil) it stops the unit if systemd
// reports it active — regardless of whether this process started it —
// and removes the generated config file.
//
// Fail-closed (#1778): a restart failure (or a failure to stop an
// active unit that is no longer in config) is returned to the caller
// so a config commit surfaces the failure instead of reporting
// success while no DHCP service is running. A nil return can also
// mean the request was superseded by a newer applier (gen ordering);
// being superseded is not a failure — the newer desired state won.
func (m *Manager) Apply(cfg *config.DHCPServerConfig) error {
	return m.apply(m.applyGen.Add(1), cfg, true)
}

// ApplyClusterCommit reconciles for a cluster-mode config commit
// (#1835 F3). Configured families ALWAYS get a freshly generated
// config file — so a dhcp-server config change is not lost until the
// next VRRP transition — but the unit is restarted only when systemd
// reports it active: an active unit means this node is currently
// serving (VRRP MASTER for the relevant RGs), so the change must
// reach the running Kea now. Inactive units stay stopped with the
// fresh config on disk; the next VRRP MASTER transition's Apply
// starts them. Unconfigured families are cleared exactly as in Apply.
// Fail-closed like Apply: generate/restart/stop failures are returned
// so the commit surfaces them.
func (m *Manager) ApplyClusterCommit(cfg *config.DHCPServerConfig) error {
	return m.apply(m.applyGen.Add(1), cfg, false)
}

// apply is the shared reconcile body for every applier (sync Apply,
// sync ApplyClusterCommit, async worker). gen is the caller's
// generation, allocated at call entry; a request older than the
// newest applied desired state is skipped (superseded — Codex hole 2
// on PR #1835: without this, a queued async request could be applied
// OVER a later synchronous commit's fresh config). restartInactive
// selects whether a configured family's unit is restarted
// unconditionally (standalone / VRRP-MASTER semantics) or only when
// already active (cluster commit semantics, see ApplyClusterCommit).
func (m *Manager) apply(gen uint64, cfg *config.DHCPServerConfig, restartInactive bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if gen <= m.lastAppliedGen {
		// A newer desired state has already been applied (or
		// attempted). Skipping is correct, not an error: the caller's
		// state was superseded before it reached the reconcile body.
		m.staleApplySkips.Add(1)
		slog.Debug("skipping superseded DHCP server apply",
			"gen", gen, "last_applied_gen", m.lastAppliedGen)
		return nil
	}

	// #6787: once shutdown has latched, the only legal desired state is
	// "stopped". A VRRP MASTER transition racing the shutdown allocates a
	// NEWER generation than Shutdown's own apply, so the supersession guard
	// above cannot stop it re-arming Kea after this node has begun
	// relinquishing ownership — which is precisely how both nodes end up
	// serving DHCP on one segment.
	if m.shuttingDown.Load() {
		cfg = nil
	}

	var errs []error

	want4 := cfg != nil && cfg.DHCPLocalServer != nil && len(cfg.DHCPLocalServer.Groups) > 0
	want6 := cfg != nil && cfg.DHCPv6LocalServer != nil && len(cfg.DHCPv6LocalServer.Groups) > 0

	if want4 {
		if err := m.generateKea4Config(cfg); err != nil {
			errs = append(errs, fmt.Errorf("generate kea4 config: %w", err))
		} else if err := m.reconcileFamilyRestart(kea4Svc, restartInactive); err != nil {
			errs = append(errs, err)
		}
	} else if err := m.clearFamilyLocked(kea4Svc, m.confPath4); err != nil {
		errs = append(errs, err)
	}

	if want6 {
		if err := m.generateKea6Config(cfg); err != nil {
			errs = append(errs, fmt.Errorf("generate kea6 config: %w", err))
		} else if err := m.reconcileFamilyRestart(kea6Svc, restartInactive); err != nil {
			errs = append(errs, err)
		}
	} else if err := m.clearFamilyLocked(kea6Svc, m.confPath6); err != nil {
		errs = append(errs, err)
	}

	m.lastAppliedGen = gen
	err := errors.Join(errs...)
	// #6535: remember whether this attempt actually converged, so a
	// converger can re-drive it. lastAppliedGen deliberately still advances
	// on failure (see its doc comment) — a retry allocates a FRESH gen from
	// applyGen, so it is never blocked by the superseded guard, and leaving
	// the ordering invariant untouched keeps the #1835 coalescing reasoning
	// intact.
	m.noteApplyOutcome(err)
	return err
}

// noteApplyOutcome records whether a completed apply converged. Separate from
// apply's body so the retry state lives under retryMu rather than mu.
func (m *Manager) noteApplyOutcome(err error) {
	m.retryMu.Lock()
	defer m.retryMu.Unlock()
	m.applyFailed = err != nil
}

// applyRetryInterval is the minimum spacing between converger-driven retries
// of a failed apply. A Kea apply regenerates config and shells out to
// systemctl under a 15 s bound; the reconcile loop that drives the retry ticks
// every 2 s, so retrying on every tick would keep a permanently broken Kea
// (missing binary, bad unit) in a continuous restart shell-out. 30 s heals a
// transient fault well inside an operator's notice without that.
const applyRetryInterval = 30 * time.Second

// ClaimApplyRetry reports whether a converger should re-drive the desired
// state because the last completed apply attempt failed, and CLAIMS the retry
// window when it says yes (#6535).
//
// It is a claim rather than a plain predicate for the same reason
// rgStateMachine.ShouldLogRetry is: the caller acts on the answer, and two
// passes must not both act. A caller that claims and then does not enqueue
// only loses one window — the next one re-claims, so it cannot wedge.
//
// The flag is cleared by the next SUCCESSFUL apply, not by the claim, so a
// retry that fails again stays claimable.
func (m *Manager) ClaimApplyRetry(now time.Time) bool {
	m.retryMu.Lock()
	defer m.retryMu.Unlock()
	if !m.applyFailed {
		return false
	}
	if !m.lastRetryClaim.IsZero() && now.Sub(m.lastRetryClaim) < applyRetryInterval {
		return false
	}
	m.lastRetryClaim = now
	return true
}

// Shutdown performs the authoritative DHCP-server stop for daemon shutdown
// (#6787) and is the ONLY stop on that path — before it, an orderly HA
// shutdown withdrew VRRP ownership, cleared rg_active, and stopped the
// heartbeat while leaving the Kea units RUNNING. The peer promoted and started
// its own Kea, so both nodes served DHCP on the same segment: duplicate
// OFFERs, and two lease databases handing out the same addresses with neither
// aware of the other.
//
// It is SYNCHRONOUS on purpose. ApplyAsync's mailbox is drained by a worker
// goroutine, so a stop enqueued during shutdown races process exit and is
// simply lost — the failure mode is "the fix is present and does nothing",
// which looks identical to working. The commit path already has a synchronous
// applier for exactly this reason.
//
// It also LATCHES (see shuttingDown). Shutdown runs before the priority-0
// withdrawal so this node stops serving before the peer starts serving, and
// that ordering leaves a window in which a VRRP MASTER transition can enqueue
// an apply with a NEWER generation. Stopping without latching would let that
// window re-arm the units after the stop had "succeeded".
//
// The error is returned rather than logged so a caller can report a Kea that
// refused to stop; the units are separate systemd services, so a failure here
// means they are still serving and the operator needs to know.
func (m *Manager) Shutdown() error {
	m.shuttingDown.Store(true)
	return m.apply(m.applyGen.Add(1), nil, true)
}

// ApplyAsync enqueues an authoritative Apply for cfg and returns
// immediately (#1835 F2). The VRRP event loop calls the Kea manager on
// MASTER/BACKUP transitions; running Apply inline there would hold the
// loop for up to 15s per systemctl shell-out. Instead, desired states
// go through a 1-slot latest-wins mailbox drained by a single worker
// goroutine (started lazily, once per Manager).
//
// Latest-wins coalescing is correct because Apply is an idempotent
// reconcile to the desired state: when transitions arrive faster than
// systemctl completes, intermediate states may be skipped, but the
// newest desired state always wins — the mailbox slot is monotonic in
// gen, and the shared apply body skips any request superseded by a
// newer applier (sync OR async). Pass cfg == nil for an authoritative
// clear (same semantics as Apply(nil)). Errors are logged by the
// worker with the supplied reason; callers that need fail-closed
// errors (the commit path) use the synchronous Apply instead.
func (m *Manager) ApplyAsync(cfg *config.DHCPServerConfig, reason string) {
	m.enqueueAsync(&asyncApplyReq{
		gen:    m.applyGen.Add(1),
		cfg:    cfg,
		reason: reason,
	})
}

// enqueueAsync installs req in the pending slot iff it is the newest
// async request seen, then wakes the singleton worker. Split from
// ApplyAsync so tests can inject a request whose gen was allocated
// earlier (modeling a producer preempted between call entry and
// enqueue — the interleaving behind Codex hole 1).
//
// The gen guard on the overwrite (not unconditional) closes the
// async-vs-async ABA residue: two producers can allocate gens in one
// order and reach this mutex in the other; an unconditional overwrite
// would let the older gen replace the newer one, and with the newer
// gen never applied the lastAppliedGen check could not save it.
func (m *Manager) enqueueAsync(req *asyncApplyReq) {
	m.asyncOnce.Do(func() {
		m.asyncNotify = make(chan struct{}, 1)
		m.asyncWorkerStarts.Add(1)
		go m.applyAsyncWorker()
	})
	m.asyncMu.Lock()
	if m.pendingAsync == nil || req.gen > m.pendingAsync.gen {
		m.pendingAsync = req
	}
	m.asyncMu.Unlock()
	// Non-blocking wake: a token already in flight covers this set
	// too (the worker re-reads pendingAsync after every wake).
	select {
	case m.asyncNotify <- struct{}{}:
	default:
	}
}

// applyAsyncWorker is the singleton consumer for ApplyAsync. It runs
// for the daemon's lifetime (the wake channel is never closed); each
// wake takes the pending desired state (leaving the slot empty) and
// runs the shared gen-checked apply body under the normal m.mu
// serialization with synchronous appliers.
func (m *Manager) applyAsyncWorker() {
	for range m.asyncNotify {
		m.asyncMu.Lock()
		req := m.pendingAsync
		m.pendingAsync = nil
		m.asyncMu.Unlock()
		if req == nil {
			continue
		}
		if err := m.apply(req.gen, req.cfg, true); err != nil {
			slog.Warn("async DHCP server apply failed",
				"reason", req.reason, "gen", req.gen, "err", err)
		}
	}
}

// reconcileFamilyRestart restarts a Kea unit whose config was just
// regenerated. It restarts when the unit is already active (to pick up
// the fresh config) or when restartInactive is set (cluster-commit
// semantics: bring the unit up even if it was down). Caller must hold
// m.mu.
//
// Fail-closed (#4870 A): if the `systemctl is-active` query itself fails
// (timeout/exec error, not a definitive "inactive"), the previous code
// mapped the uncertainty to "inactive" and SKIPPED the restart, so on a
// cluster commit a transient blip left the old Kea process serving stale
// policy while the commit returned success. Now an uncertain query is
// treated as needing enforcement: the unit is restarted (idempotent —
// this authoritatively loads the freshly generated config) AND the query
// error is surfaced so a synchronous commit does not report success on an
// unverified enforcement.
func (m *Manager) reconcileFamilyRestart(svc string, restartInactive bool) error {
	var errs []error
	active, qerr := m.unitActive(svc)
	if qerr != nil {
		errs = append(errs, fmt.Errorf("query %s active state: %w", svc, qerr))
		slog.Warn("could not query Kea unit state; restarting to enforce config",
			"service", svc, "err", qerr)
	}
	if restartInactive || active || qerr != nil {
		if err := m.restartClearingStartLimit(svc); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// restartClearingStartLimit restarts svc, and if that fails, clears the
// unit's failed state with `systemctl reset-failed` and restarts it once more
// (#9601).
//
// systemd refuses a start once a unit has been started more than
// StartLimitBurst times within StartLimitIntervalSec ("start of the service was
// attempted too often") and keeps refusing until the interval passes or the
// failed state is reset. A node that takes several redundancy groups in one
// second enqueues one MASTER apply per edge, and each apply restarts Kea, so a
// burst can trip the limit on the node that must now serve DHCP. The #6535
// converger's retry then hit the same refusal a few seconds later, and Kea
// stayed down until an unrelated commit restarted it.
//
// The rate limit exists to stop a crash loop, and this controller already
// bounds its own retries (applyRetryInterval), so resetting it here trades
// nothing: a unit that fails for another reason fails the second restart too,
// the combined error is returned, and the apply stays failed and retryable.
// Exactly one reset and one extra restart per apply, never a loop.
func (m *Manager) restartClearingStartLimit(svc string) error {
	err := m.runSystemctl("restart", svc)
	if err == nil {
		return nil
	}
	first := fmt.Errorf("restart %s: %w", svc, err)
	if rerr := m.runSystemctl("reset-failed", svc); rerr != nil {
		return errors.Join(first, fmt.Errorf("reset-failed %s: %w", svc, rerr))
	}
	if err := m.runSystemctl("restart", svc); err != nil {
		return errors.Join(first, fmt.Errorf("restart %s after reset-failed: %w", svc, err))
	}
	slog.Info("Kea unit restarted after clearing its failed state", "service", svc, "first_error", err)
	return nil
}

// clearFamilyLocked stops one Kea unit if systemd reports it active
// and removes its generated config file. Caller must hold m.mu.
//
// Fail-closed (#4870 A): an is-active query failure no longer silently
// skips the stop (which would leave a removed subnet still served). On an
// uncertain query the stop is issued authoritatively (a stop on an
// already-inactive unit is harmless) and the query error is surfaced. The
// config-file unlink error is also surfaced now (a leftover generated
// config lets a later manual/boot start of Kea resurrect the removed
// subnet); an already-absent file is success.
func (m *Manager) clearFamilyLocked(svc, confPath string) error {
	var errs []error
	active, qerr := m.unitActive(svc)
	if qerr != nil {
		errs = append(errs, fmt.Errorf("query %s active state: %w", svc, qerr))
		slog.Warn("could not query Kea unit state; stopping to enforce removal",
			"service", svc, "err", qerr)
	}
	if active || qerr != nil {
		if e := m.runSystemctl("stop", svc); e != nil {
			errs = append(errs, fmt.Errorf("stop %s: %w", svc, e))
			slog.Warn("failed to stop Kea unit", "service", svc, "err", e)
		} else {
			slog.Info("stopped Kea unit not in current config", "service", svc)
		}
	}
	if e := os.Remove(confPath); e != nil && !os.IsNotExist(e) {
		errs = append(errs, fmt.Errorf("remove %s: %w", confPath, e))
	}
	return errors.Join(errs...)
}

// Clear stops both Kea units (if systemd reports them active) and
// removes the generated configs. Stop failures are logged at Warn by
// clearFamilyLocked; callers on the VRRP transition path (daemon_ha)
// cannot fail a state transition, so Clear keeps a void signature.
// Commit-path callers use Apply(nil) instead, which returns errors.
func (m *Manager) Clear() {
	// Delegate to Apply(nil) so a Clear participates in the same
	// generation ordering as every other applier (#1835 F2 redesign)
	// instead of silently bypassing supersession. Errors are already
	// logged at Warn by clearFamilyLocked.
	_ = m.Apply(nil)
}

// IsRunning returns true if any Kea server unit is active per systemd
// (authoritative — survives xpfd restarts, unlike the pre-#1778
// process-local booleans).
func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	// A query error is treated as not-running for this status reporter: a
	// unit whose state cannot be determined must not be reported as an
	// active DHCP server (#4870).
	a4, _ := m.unitActive(kea4Svc)
	a6, _ := m.unitActive(kea6Svc)
	return a4 || a6
}

// Lease represents a DHCP lease from Kea's lease database.
type Lease struct {
	Address    string
	HWAddress  string
	Hostname   string
	ValidLife  string
	ExpireTime string
	SubnetID   string
}

// GetLeases4 reads Kea DHCPv4 lease file and returns active leases.
func (m *Manager) GetLeases4() ([]Lease, error) {
	return parseLeaseCSV(m.leaseFile(4), time.Now())
}

// GetLeases6 reads Kea DHCPv6 lease file and returns active leases.
func (m *Manager) GetLeases6() ([]Lease, error) {
	return parseLeaseCSV(m.leaseFile(6), time.Now())
}

// parseLeaseCSV parses Kea's append-only memfile CSV set and returns the
// CURRENT, ACTIVE leases for display (`show dhcp server leases`). #5796: it
// reads the FULL Kea LFC file set (previous `.2`, input `.1`, current) and
// merges them, so the display never omits the compacted active leases that live
// in the previous/input files right after an LFC rotation.
//
// Kea never rewrites the memfile in place between lease-file-cleanup
// (LFC) compactions: every renewal, re-allocation, release, decline,
// and expiry-reclaim is APPENDED as a new row, so the same address
// appears multiple times and superseded/stale rows linger until the
// next LFC. A naive "emit every row with a non-empty address" therefore
// shows duplicate and stale leases (#2085). This parser collapses the
// append log to one row per address (the LAST, i.e. newest, row wins —
// rows are chronological) and drops rows that are not currently active:
//
//   - state != 0 (declined / expired-reclaimed): Kea writes a
//     non-default state but often a FUTURE expire epoch on
//     release/decline, so an expire-only filter would still show it.
//   - expire <= now: a genuinely lapsed lease.
//
// It is LENIENT by design (this is a non-destructive display path,
// unlike the destructive DDNS reconciler's parseActiveLeases, which
// hard-errors on a mangled header): an absent or unparseable state /
// expire column degrades to "treat the row as active", preserving the
// pre-#2085 behaviour for older Kea or exotic headers rather than
// blanking the whole `show` on one odd row. now is injected so the
// expiry comparison is deterministic in tests.
// leaseCSVAccum accumulates the lenient last-row-wins display disposition per
// address ACROSS the Kea LFC file set (#5796). A zero Lease (empty Address) is a
// TOMBSTONE meaning the last row seen for that address (in chronological
// file+row order) was inactive/expired. order keeps first-appearance order so
// the display is stable and deterministic.
type leaseCSVAccum struct {
	latest map[string]Lease
	order  []string
	seen   map[string]struct{}
}

func parseLeaseCSV(path string, now time.Time) ([]Lease, error) {
	acc := &leaseCSVAccum{
		latest: make(map[string]Lease),
		seen:   make(map[string]struct{}),
	}
	// #5796: read the whole Kea LFC file set (previous .2 → input .1 → current)
	// in chronological order and merge, so `show dhcp server leases` does not
	// omit the compacted active set that lives in the previous/input files right
	// after an LFC rotation. A missing .1/.2 (the common no-LFC case) collapses
	// the set to exactly the current file, byte-identical to the pre-#5796 read.
	for _, f := range keaLFCLeaseFilePaths(path) {
		if err := parseLeaseCSVFileInto(f, now, acc); err != nil {
			return nil, err
		}
	}

	leases := make([]Lease, 0, len(acc.order))
	for _, addr := range acc.order {
		if l := acc.latest[addr]; l.Address != "" {
			leases = append(leases, l)
		}
	}
	if len(leases) == 0 {
		return nil, nil
	}
	return leases, nil
}

// parseLeaseCSVFileInto reads ONE Kea LFC-set file into acc using the lenient
// display semantics. A genuinely-missing file is skipped (nil); a
// non-IsNotExist open error is returned so the display surfaces it.
func parseLeaseCSVFileInto(path string, now time.Time, acc *leaseCSVAccum) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	// Read the memfile RECORD-BY-RECORD rather than with ReadAll so a
	// single torn/concurrent Kea append (Kea appends a row on every
	// renewal/release/decline/reclaim while we read) does not blank the
	// entire `show dhcp server leases` (#2154). ReadAll aborts on the
	// FIRST malformed record and returns (nil, err); the per-record loop
	// logs and SKIPS the bad row, keeping every valid lease around it.
	// This is the I/O-layer companion to #2085's per-record semantic
	// leniency (dedup/expire/state) — #2085 made the SEMANTICS lenient
	// but left the READ all-or-nothing.
	//
	// FieldsPerRecord = -1 means a short concurrent line is not even an
	// error; csv.Read() also RECOVERS after a *csv.ParseError (the next
	// Read returns the following valid record or io.EOF), so the skip
	// loop terminates naturally rather than spinning.
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // memfile rows can vary across Kea versions / torn appends
	r.Comment = '#'

	// cols maps header name -> column index; it stays nil until the
	// first successful record (the header) is read. field() reads a named
	// column out of a data row. cols is FILE-LOCAL: each LFC-set file
	// carries its own header.
	var cols map[string]int
	field := func(fields []string, name string) string {
		if idx, ok := cols[name]; ok && idx >= 0 && idx < len(fields) {
			return fields[idx]
		}
		return ""
	}
	nowUnix := now.Unix()

	for {
		fields, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Torn/concurrent Kea append or an exotic malformed row.
			// Skip just this record and keep reading the rest (#2154);
			// csv.Read recovers on the next call. Debug, not Warn: a
			// persistently corrupt file is polled once per `show`, and
			// the issue mandates debug-level so a busy network does not
			// spam the log.
			slog.Debug("dhcpserver: skipping malformed lease row",
				"path", path, "err", err)
			continue
		}
		if cols == nil {
			// First successful record is the header; build the column
			// index map and move on (mirrors the old records[0]). A file
			// with no header at all contributes nothing (the lenient
			// display never errors on it).
			cols = make(map[string]int, len(fields))
			for i, h := range fields {
				cols[h] = i
			}
			continue
		}

		addr := field(fields, "address")
		if addr == "" {
			continue
		}
		if _, ok := acc.seen[addr]; !ok {
			acc.seen[addr] = struct{}{}
			acc.order = append(acc.order, addr)
		}

		// State filter (lenient): only Kea's default state (0 = active)
		// is displayable. A declined (1) or expired-reclaimed (2) lease
		// can still carry a FUTURE expire epoch, so this must precede the
		// expire check. An absent/unparseable state ⇒ active (Kea
		// default). A non-active row tombstones the address; a later
		// active append can still reclaim it.
		if s := field(fields, "state"); s != "" {
			if st, e := strconv.Atoi(s); e == nil && st != 0 {
				acc.latest[addr] = Lease{}
				continue
			}
		}

		// Expire filter (lenient): drop a lease whose expire epoch has
		// lapsed. Absent/unparseable/zero expire ⇒ keep (don't hide a
		// lease over an exotic value on a display).
		expireStr := field(fields, "expire")
		if expireStr != "" {
			if exp, e := strconv.ParseInt(expireStr, 10, 64); e == nil && exp > 0 && nowUnix >= exp {
				acc.latest[addr] = Lease{}
				continue
			}
		}

		acc.latest[addr] = Lease{
			Address:    addr,
			HWAddress:  field(fields, "hwaddr"),
			Hostname:   field(fields, "hostname"),
			ValidLife:  field(fields, "valid_lifetime"),
			ExpireTime: expireStr,
			SubnetID:   field(fields, "subnet_id"),
		}
	}

	return nil
}

// subnetInterface returns the per-subnet interface binding for a
// group. Kea allows at most ONE interface per subnet; for a
// single-interface group binding it explicitly is the most robust
// selection. For multi-interface groups the binding is omitted so Kea
// falls back to address-based subnet selection (matching the address
// of the receiving interface against the subnet prefix) — the
// pre-#1778 renderer silently bound only the first interface,
// breaking the others. All group interfaces are always listed in
// interfaces-config, so Kea listens on every one either way.
//
// #6520: the single-interface inference is only sound for a group whose member
// list is what the operator AUTHORED. A group narrowed at runtime by the
// chassis-cluster master-RG filter can arrive here as a singleton while still
// carrying the pools of the members that were removed, and binding those pools
// to the survivor cross-binds a foreign network onto it. There is no
// pool→member edge in the config model to filter the pools by, so a narrowed
// group falls back to address-based selection — the same mechanism every
// multi-interface group already uses, and correct for the pools that DO belong
// to the survivor.
func subnetInterface(group *config.DHCPServerGroup) string {
	if group.MembersFiltered {
		return ""
	}
	if len(group.Interfaces) == 1 {
		return group.Interfaces[0]
	}
	return ""
}

// warnAmbiguousV4SubnetSelection warns when two DIFFERENT groups render
// the same or overlapping v4 subnets while at least one of the involved
// groups emits no per-subnet interface selector (multi-interface groups,
// see subnetInterface). Kea's subnet selection is then ambiguous: a
// DISCOVER arriving on a shared interface can match either subnet, so
// which pool answers is undefined. This stays a WARNING, not an error —
// such configs were accepted before #1778 and must keep committing.
func (m *Manager) warnAmbiguousV4SubnetSelection(srv *config.DHCPLocalServerConfig) {
	type subnetRef struct {
		group    string
		subnet   string
		prefix   netip.Prefix
		selector bool // group emits a per-subnet interface selector
	}
	var refs []subnetRef
	for name, group := range srv.Groups {
		sel := subnetInterface(group) != ""
		for _, pool := range group.Pools {
			p, err := netip.ParsePrefix(pool.Subnet)
			if err != nil {
				continue // Kea rejects the malformed subnet itself
			}
			refs = append(refs, subnetRef{
				group: name, subnet: pool.Subnet,
				prefix: p.Masked(), selector: sel,
			})
		}
	}
	for i := 0; i < len(refs); i++ {
		for j := i + 1; j < len(refs); j++ {
			a, b := refs[i], refs[j]
			if a.group == b.group || (a.selector && b.selector) {
				continue
			}
			if a.prefix.Overlaps(b.prefix) {
				m.warn("ambiguous Kea subnet selection: overlapping subnets across groups without per-subnet interface selectors",
					"group_a", a.group, "subnet_a", a.subnet,
					"group_b", b.group, "subnet_b", b.subnet)
			}
		}
	}
}

// canonicalMAC normalizes a static-binding MAC to Kea's accepted
// colon-separated lowercase form (aa:bb:cc:dd:ee:ff). ValidateMAC at
// commit accepts Go's net.ParseMAC inputs, which include the Cisco
// dotted-triplet form (0011.2233.4455) and uppercase — but Kea's
// hw-address parser REJECTS the dotted form, so a config that commits
// clean would otherwise break the entire Kea Dhcp4/6 reconfigure (parse
// failure -> server down). Render canonically. The MAC was already
// validated at commit, so a parse error here is not expected; on the
// off chance it occurs we report it so the caller can skip the entry
// (consistent with the tolerant-load skip guard) rather than emit a
// malformed reservation.
func canonicalMAC(mac string) (string, bool) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return "", false
	}
	return hw.String(), true
}

// keaExpiredLeasesMap renders the per-family `expired-leases-processing`
// reclamation block (#1387 stale-lease-cleanup slice / Path S), or nil
// when the block is absent OR disabled. Returning nil makes the caller
// omit the key entirely, so the generated Kea config is BYTE-IDENTICAL to
// the pre-#1387 output (invariant H1, the cardinal compatibility
// invariant — the disabled/nil omit is UNCONDITIONAL).
//
// Each numeric field is emitted only when set, so an operator can tune one
// knob without pinning the rest to a value we invented. The two CAP knobs
// (max-reclaim-leases / max-reclaim-time) emit on the model's *Set bool,
// NOT on `> 0`, because 0 means UNLIMITED in Kea — a value distinct from
// "omit -> Kea default" (invariant H2).
//
// When Enabled is true but no knob is configured this returns a non-nil
// empty map, so the caller emits `"expired-leases-processing": {}` — Kea
// reads an empty block as "reclamation with built-in defaults," and
// surfacing the empty block lets an operator see the feature is on in the
// rendered config.
func keaExpiredLeasesMap(c *config.DHCPExpiredLeasesConfig) map[string]any {
	if c == nil || !c.Enabled {
		return nil
	}
	m := map[string]any{}
	if c.ReclaimTimerWait > 0 {
		m["reclaim-timer-wait-time"] = c.ReclaimTimerWait
	}
	if c.FlushReclaimedTimerWait > 0 {
		m["flush-reclaimed-timer-wait-time"] = c.FlushReclaimedTimerWait
	}
	if c.HoldReclaimedTime > 0 {
		m["hold-reclaimed-time"] = c.HoldReclaimedTime
	}
	if c.MaxReclaimLeasesSet {
		m["max-reclaim-leases"] = c.MaxReclaimLeases // 0 == unlimited, intentional (H2)
	}
	if c.MaxReclaimTimeSet {
		m["max-reclaim-time"] = c.MaxReclaimTime // 0 == unlimited, intentional (H2)
	}
	if c.UnwarnedReclaimCycles > 0 {
		m["unwarned-reclaim-cycles"] = c.UnwarnedReclaimCycles
	}
	return m
}

// stableGroups returns the DHCP server groups in a DETERMINISTIC,
// reload-stable order (#2668). The config holds groups in a Go map whose
// iteration order is randomized, so assigning Kea subnet_id over a direct
// map range produced a different ID for the same subnet on every config
// regeneration. Sorting by the group name (the map key) gives the same
// subnet the same subnet_id across reloads of an unchanged config, which is
// what Kea needs to keep memfile leases bound to the right subnet. The map
// key is mirrored into DHCPServerGroup.Name by the compiler, but we sort on
// the authoritative map key so a (hypothetical) name/key mismatch cannot
// reintroduce nondeterminism.
func stableGroups(groups map[string]*config.DHCPServerGroup) []*config.DHCPServerGroup {
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]*config.DHCPServerGroup, 0, len(names))
	for _, name := range names {
		out = append(out, groups[name])
	}
	return out
}

// stablePools returns a group's pools in a deterministic order (#2668).
// Pools already arrive as a config-declared slice (stable across reloads of
// an unchanged config), but sorting by the pool subnet (then name) hardens
// the subnet_id assignment against a pool being reordered within a group:
// the subnet string is the natural key Kea uses to bind a lease, so a pool
// keeps its subnet_id even if its position in the group's list shifts. It
// returns a fresh slice — the caller's config is not mutated.
func stablePools(pools []*config.DHCPPool) []*config.DHCPPool {
	out := make([]*config.DHCPPool, len(pools))
	copy(out, pools)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Subnet != out[j].Subnet {
			return out[i].Subnet < out[j].Subnet
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// keaSubnetIDMax is the largest Kea subnet-id we assign. Kea subnet-ids are
// uint32 with two reserved sentinels: 0 (SUBNET_ID_UNUSED) and 0xFFFFFFFF
// (SUBNET_ID_GLOBAL). We therefore map into the closed range
// [1, 0xFFFFFFFE].
const keaSubnetIDMax = 0xFFFFFFFE

// #8597 K53: a COMPILE-TIME assertion that `int` is wide enough to hold
// keaSubnetIDMax, because stableSubnetID below returns `int` and its modulo can
// produce any value in [0, keaSubnetIDMax-1].
//
// On a 32-bit `int` (GOARCH=386, 32-bit arm) every result above 0x7FFFFFFF —
// roughly half of all subnets — wraps NEGATIVE, and a negative Kea subnet-id is
// not a diagnosable error: it is written into the generated Kea config and the
// daemon rejects or misfiles the subnet, on about half the subnets, chosen by a
// hash nobody can predict from the config.
//
// Today that cannot happen, and the reason is not a check — it is that this
// tree builds only amd64 and arm64, both LP64. So the arithmetic is correct
// because of a BUILD-TARGET property that nothing states. This line states it.
// `int(keaSubnetIDMax)` is a constant conversion: on a 64-bit target it is
// trivially fine, and on a 32-bit one the compiler refuses with
// "constant 4294967294 overflows int" — naming the constant, at build time, on
// the day someone adds the target rather than in the field afterwards.
//
// A range check here would be the wrong remedy: it would be dead code on every
// target we build, which is the dead-guard class #6780 exists to prevent.
const _ = int(keaSubnetIDMax)

// stableSubnetID derives a DETERMINISTIC Kea subnet-id from the subnet's
// canonical CIDR identity (#5041). The prior scheme was a positional counter
// (subnetID := 1; subnetID++) over each node's list of subnets. In an HA
// cluster each node renders only its MASTER-filtered subset
// (filterDHCPConfigForMasterRGs), so the SAME logical subnet landed at a
// DIFFERENT position — and thus a DIFFERENT subnet_id — on the two nodes. A
// synced lease carries its subnet_id verbatim, so it misbound on the receiver
// (Kea rejected it or bound it to the wrong subnet), defeating the
// duplicate-allocation protection lease sync exists to provide.
//
// Hashing the CIDR string makes the id a pure function of the subnet identity:
// the same subnet gets the same id on both nodes regardless of the
// MASTER-filtered subset, group ordering, or failover generation — the #5041
// invariant. The #2668 property (stable across reloads of an unchanged config)
// is subsumed. Distinct id spaces per family are irrelevant here: v4 and v6 are
// separate Kea daemons with independent subnet_id spaces, and a synced lease is
// seeded into the daemon matching its family, so we hash the CIDR alone.
func stableSubnetID(subnet string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(subnet))
	// Fold uint32 into [1, keaSubnetIDMax].
	return int(h.Sum32()%keaSubnetIDMax) + 1
}

// subnetProbeStep derives a DETERMINISTIC probe step from the subnet CIDR
// ALONE, using a DIFFERENT FNV-1a seed than stableSubnetID (a fixed salt
// prefix). It is only consulted to resolve the astronomically unlikely case of
// two DISTINCT CIDRs in the SAME rendered config hashing to the same id
// (#5203). Because the step is a pure function of the CIDR — never of the
// node's MASTER-filtered subset — a colliding subnet walks the SAME probe
// sequence on both HA nodes, so it resolves to the SAME id regardless of which
// OTHER subnets each node masters. This is the completeness residual of #5041:
// the earlier +1 linear probe stepped through the node's render order, so the
// free id it found depended on the surrounding subnets and could differ across
// nodes under asymmetric mastering, reintroducing the #5041 cross-node misbind
// for the colliding pair.
//
// The step is forced coprime with keaSubnetIDMax so the linear probe over
// (base + k*step) visits every id in [1, keaSubnetIDMax] exactly once and thus
// always finds a free slot (there are always far fewer than keaSubnetIDMax
// subnets). keaSubnetIDMax == 0xFFFFFFFE == 2 * (2^31-1) with 2^31-1 prime, so
// an odd step is coprime unless it equals that prime factor; we bump that one
// residue.
func subnetProbeStep(subnet string) uint32 {
	h := fnv.New32a()
	// Distinct seed from stableSubnetID (which hashes the raw CIDR bytes): the
	// salt makes this an INDEPENDENT hash so base and step do not correlate.
	_, _ = h.Write([]byte("xpf-subnet-probe\x00"))
	_, _ = h.Write([]byte(subnet))
	step := h.Sum32() % uint32(keaSubnetIDMax) // [0, keaSubnetIDMax-1]
	step |= 1                                  // odd -> coprime with the 2 factor
	if step == 0x7FFFFFFF {                    // == 2^31-1, the only odd non-coprime residue
		step += 2
	}
	return step
}

// resolveSubnetID returns the Kea subnet-id to assign to subnet given the ids
// already claimed by earlier subnets in the SAME rendered config (used). The
// common path is the direct stableSubnetID hit — no collision — returned
// unchanged so realistic deployments are bit-identical to #5041. On a genuine
// hash collision the loser walks a CIDR-DERIVED sequence base + k*step (folded
// into [1, keaSubnetIDMax]) until it finds a free id, skipping occupied ids in
// a CIDR-DETERMINED order rather than the set-position order the old +1 probe
// used. Two subnets on a single Kea instance must never share an id (Kea would
// misbind), and 0 / 0xFFFFFFFF (Kea's reserved sentinels) are never produced.
func resolveSubnetID(subnet string, used map[int]bool) int {
	id := stableSubnetID(subnet)
	if !used[id] {
		return id
	}
	m := uint64(keaSubnetIDMax)
	step := uint64(subnetProbeStep(subnet))
	cur := uint64(id - 1) // 0-based, in [0, keaSubnetIDMax-1]
	for k := uint64(1); k < m; k++ {
		cur += step
		if cur >= m {
			cur -= m // step < m, so cur < 2m: one subtraction re-folds
		}
		cand := int(cur) + 1
		if !used[cand] {
			return cand
		}
	}
	return id // unreachable: subnet count is always << keaSubnetIDMax
}

func (m *Manager) generateKea4Config(cfg *config.DHCPServerConfig) error {
	type keaPool struct {
		Pool string `json:"pool"`
	}
	type keaOpt struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}
	type keaReservation struct {
		HWAddress string `json:"hw-address"`
		IPAddress string `json:"ip-address"`
		Hostname  string `json:"hostname,omitempty"`
	}
	type keaSubnet4 struct {
		ID            int              `json:"id"`
		Subnet        string           `json:"subnet"`
		Pools         []keaPool        `json:"pools,omitempty"`
		Interface     string           `json:"interface,omitempty"`
		OptionData    []keaOpt         `json:"option-data,omitempty"`
		ValidLifetime int              `json:"valid-lifetime,omitempty"`
		Reservations  []keaReservation `json:"reservations,omitempty"`
	}

	m.warnAmbiguousV4SubnetSelection(cfg.DHCPLocalServer)

	var subnets []keaSubnet4
	usedIDs := make(map[int]bool)
	seenSubnets := make(map[netip.Prefix]string) // #9785: claimPoolSubnet
	// #5041/#2668/#5203: assign Kea subnet_id from a STABLE hash of the subnet
	// CIDR, walking a DETERMINISTIC (sorted-group, sorted-pool) order. Kea binds
	// memfile leases (kea-leases4.csv) to subnets by the subnet_id column. The
	// prior positional counter gave the SAME subnet a DIFFERENT id on the two
	// HA nodes because each renders only its MASTER-filtered subset, so a
	// synced lease misbound on the receiver (#5041). Hashing the CIDR makes the
	// id a function of the subnet identity alone — identical on both nodes,
	// across filtered subsets and reloads (#2668). On the astronomically rare
	// hash collision, resolveSubnetID probes a CIDR-DERIVED sequence (not the
	// node's set position), so even the colliding pair resolves to the same id
	// on both nodes (#5203).
	for _, group := range stableGroups(cfg.DHCPLocalServer.Groups) {
		for _, pool := range stablePools(group.Pools) {
			if kept, dup := claimPoolSubnet(seenSubnets, group.Name, pool); dup {
				m.warn("skipping DHCP pool whose subnet duplicates one already rendered (Kea refuses a second subnet with the same prefix)",
					"group", group.Name, "pool", pool.Name, "subnet", pool.Subnet, "kept", kept)
				continue
			}
			id := resolveSubnetID(pool.Subnet, usedIDs)
			usedIDs[id] = true
			sub := keaSubnet4{
				ID:     id,
				Subnet: pool.Subnet,
			}
			if pool.RangeLow != "" && pool.RangeHigh != "" {
				sub.Pools = append(sub.Pools, keaPool{
					Pool: fmt.Sprintf("%s - %s", pool.RangeLow, pool.RangeHigh),
				})
			}
			sub.Interface = subnetInterface(group)
			if pool.Router != "" {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "routers", Data: pool.Router,
				})
			}
			if len(pool.DNSServers) > 0 {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "domain-name-servers", Data: strings.Join(pool.DNSServers, ", "),
				})
			}
			if pool.Domain != "" {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "domain-name", Data: pool.Domain,
				})
			}
			if pool.LeaseTime > 0 {
				sub.ValidLifetime = pool.LeaseTime
			}
			// #2243: per-subnet static (fixed/reserved) host reservations.
			// Each binds a client hw-address to a fixed ip-address; the
			// matching client always receives that address. Commit-time
			// validation (validateDHCPStaticBindingsStrict) has already
			// rejected a malformed MAC, an out-of-subnet address, or a
			// duplicate identity/address, so the render is a direct mapping.
			for _, sb := range pool.StaticBindings {
				if sb == nil || sb.MACAddress == "" || sb.FixedAddress == "" {
					continue
				}
				hw, ok := canonicalMAC(sb.MACAddress)
				if !ok {
					m.warn("skipping DHCP static binding with unparseable MAC",
						"group", group.Name, "mac", sb.MACAddress)
					continue
				}
				sub.Reservations = append(sub.Reservations, keaReservation{
					HWAddress: hw,
					IPAddress: sb.FixedAddress,
					Hostname:  sb.HostName,
				})
			}
			subnets = append(subnets, sub)
		}
	}

	// Collect interfaces. Sorted group order (#2668) also keeps this list
	// deterministic across reloads.
	var ifaces []string
	for _, group := range stableGroups(cfg.DHCPLocalServer.Groups) {
		ifaces = append(ifaces, group.Interfaces...)
	}

	// #7318: `dhcp-socket-type` is emitted ONLY when the operator selected one.
	// Omitting it is not the same as writing "raw" in the config file, but it
	// IS the same to Kea (raw is its documented default), and omitting keeps
	// every pre-#7318 config rendering byte-for-byte identically.
	ifacesCfg := map[string]any{
		"interfaces": ifaces,
	}
	if st := cfg.DHCPLocalServer.SocketType; st != "" {
		ifacesCfg["dhcp-socket-type"] = st
	}

	dhcp4 := map[string]any{
		"interfaces-config": ifacesCfg,
		"lease-database": map[string]any{
			"type": "memfile",
			"name": keaLeaseFile4,
		},
		"valid-lifetime": 86400,
		"subnet4":        subnets,
	}
	// #1387: opt-in expired-lease reclamation tuning. nil/disabled -> key
	// omitted -> byte-identical to pre-#1387 (H1).
	if elp := keaExpiredLeasesMap(cfg.DHCPLocalServer.ExpiredLeases); elp != nil {
		dhcp4["expired-leases-processing"] = elp
	}
	m.addLeaseSyncStanza(dhcp4, 4)
	keaCfg := map[string]any{"Dhcp4": dhcp4}

	return m.writeKeaConfig(m.confPath4, keaCfg)
}

func (m *Manager) generateKea6Config(cfg *config.DHCPServerConfig) error {
	type keaPool struct {
		Pool string `json:"pool"`
	}
	type keaOpt struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}
	// Kea DHCPv6 reservations bind an identity (hw-address / duid) to an
	// ARRAY of addresses (ip-addresses), unlike v4's scalar ip-address.
	// #2243 reserves by client hardware address with a single fixed
	// address.
	type keaReservation6 struct {
		HWAddress   string   `json:"hw-address"`
		IPAddresses []string `json:"ip-addresses"`
		Hostname    string   `json:"hostname,omitempty"`
	}
	type keaSubnet6 struct {
		ID            int               `json:"id"`
		Subnet        string            `json:"subnet"`
		Pools         []keaPool         `json:"pools,omitempty"`
		Interface     string            `json:"interface,omitempty"`
		OptionData    []keaOpt          `json:"option-data,omitempty"`
		ValidLifetime int               `json:"valid-lifetime,omitempty"`
		Reservations  []keaReservation6 `json:"reservations,omitempty"`
	}

	var subnets []keaSubnet6
	usedIDs := make(map[int]bool)
	seenSubnets := make(map[netip.Prefix]string) // #9785: claimPoolSubnet
	// #5041/#2668/#5203: same stable-hash subnet_id assignment as the v4 path.
	// Kea binds kea-leases6.csv leases by subnet_id, so a positional counter
	// over each node's MASTER-filtered subset gave one subnet different ids on
	// the two nodes and misbound synced leases. Hash the CIDR so the id is
	// stable per subnet across nodes, filtered subsets, and reloads; on a hash
	// collision resolveSubnetID probes a CIDR-DERIVED sequence so the colliding
	// pair still resolves identically on both nodes (#5203).
	for _, group := range stableGroups(cfg.DHCPv6LocalServer.Groups) {
		for _, pool := range stablePools(group.Pools) {
			if kept, dup := claimPoolSubnet(seenSubnets, group.Name, pool); dup {
				m.warn("skipping DHCP pool whose subnet duplicates one already rendered (Kea refuses a second subnet with the same prefix)",
					"group", group.Name, "pool", pool.Name, "subnet", pool.Subnet, "kept", kept)
				continue
			}
			id := resolveSubnetID(pool.Subnet, usedIDs)
			usedIDs[id] = true
			sub := keaSubnet6{
				ID:     id,
				Subnet: pool.Subnet,
			}
			if pool.RangeLow != "" && pool.RangeHigh != "" {
				sub.Pools = append(sub.Pools, keaPool{
					Pool: fmt.Sprintf("%s - %s", pool.RangeLow, pool.RangeHigh),
				})
			}
			// Kea v6 subnet selection cannot fall back to address
			// matching the way v4 can (clients talk from link-local
			// source addresses), so subnet6 REQUIRES the interface
			// selector — silently omitting it for a multi-interface
			// group would orphan the subnet (Codex review on PR
			// #1835). Reject loudly; the operator splits the group.
			if len(group.Interfaces) > 1 {
				return fmt.Errorf("DHCPv6 group spanning interfaces %v: Kea subnet6 requires a single interface selector — split the group per interface", group.Interfaces)
			}
			// #9122: a group NARROWED by the RG member filter must be refused
			// too, and it is a DIFFERENT state from the one above with a
			// different remedy, so it gets its own message rather than being
			// folded into that one.
			//
			// `subnetInterface` returns "" first on MembersFiltered, so the
			// check above no longer trips — it sees the FILTERED list, which is
			// a singleton — and the subnet renders with NO interface selector,
			// contradicting the invariant three lines up. Kea then cannot select
			// the subnet for a link-local SOLICIT: a silent, total DHCPv6 outage
			// for that group with no error anywhere.
			//
			// This is the STEADY STATE, not a failover transient.
			// filterDHCPConfigForMasterRGs is driven by the 2s periodic
			// converger as well as by RG edges, so for a v6 group spanning two
			// RGs in an active/active cluster BOTH nodes render it this way
			// continuously.
			//
			// #6520's remedy — fall back to address-based selection — is valid
			// for v4 and INVALID for v6 by this file's own comment: v6 clients
			// talk from link-local sources, so there is no address to match on.
			// The v4 suppression is deliberately left untouched.
			//
			// Emphatically NOT `group.Interfaces[0]`: that binds the REMOVED
			// member's pool to the survivor's interface, which is exactly the
			// cross-bind #6520 was filed to stop, re-opened for v6. Kea would
			// lease a foreign prefix on that link.
			if group.MembersFiltered {
				return fmt.Errorf("DHCPv6 group %q was narrowed to interfaces %v by redundancy-group membership: Kea subnet6 requires an interface selector and v6 has no address-based fallback, so the subnet would be unselectable — author one DHCPv6 group per redundancy group instead of one spanning several", group.Name, group.Interfaces)
			}
			sub.Interface = subnetInterface(group)
			if len(pool.DNSServers) > 0 {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "dns-servers", Data: strings.Join(pool.DNSServers, ", "),
				})
			}
			if pool.Domain != "" {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "domain-search", Data: pool.Domain,
				})
			}
			if pool.LeaseTime > 0 {
				sub.ValidLifetime = pool.LeaseTime
			}
			// #2243: per-subnet static (fixed/reserved) host reservations.
			// v6 binds hw-address -> ip-addresses array. Commit-time
			// validation already rejected malformed / out-of-subnet /
			// duplicate bindings.
			for _, sb := range pool.StaticBindings {
				if sb == nil || sb.MACAddress == "" || sb.FixedAddress == "" {
					continue
				}
				hw, ok := canonicalMAC(sb.MACAddress)
				if !ok {
					m.warn("skipping DHCPv6 static binding with unparseable MAC",
						"group", group.Name, "mac", sb.MACAddress)
					continue
				}
				sub.Reservations = append(sub.Reservations, keaReservation6{
					HWAddress:   hw,
					IPAddresses: []string{sb.FixedAddress},
					Hostname:    sb.HostName,
				})
			}
			subnets = append(subnets, sub)
		}
	}

	// Sorted group order (#2668) keeps this list deterministic across reloads.
	var ifaces []string
	for _, group := range stableGroups(cfg.DHCPv6LocalServer.Groups) {
		ifaces = append(ifaces, group.Interfaces...)
	}

	dhcp6 := map[string]any{
		"interfaces-config": map[string]any{
			"interfaces": ifaces,
		},
		"lease-database": map[string]any{
			"type": "memfile",
			"name": keaLeaseFile6,
		},
		"valid-lifetime": 86400,
		"subnet6":        subnets,
	}
	// #1387: opt-in expired-lease reclamation tuning. nil/disabled -> key
	// omitted -> byte-identical to pre-#1387 (H1).
	if elp := keaExpiredLeasesMap(cfg.DHCPv6LocalServer.ExpiredLeases); elp != nil {
		dhcp6["expired-leases-processing"] = elp
	}
	m.addLeaseSyncStanza(dhcp6, 6)
	keaCfg := map[string]any{"Dhcp6": dhcp6}

	return m.writeKeaConfig(m.confPath6, keaCfg)
}

// addLeaseSyncStanza injects the unix control-socket + lease_cmds hook into a
// generated Kea Dhcp{4,6} object when #2239 lease sync is enabled. When the
// knob is off (or standalone) it is a no-op, so the rendered config is
// bit-identical to pre-#2239. The control socket lets the #2239 push/seed path
// read (lease{4,6}-get-all) and write (lease{4,6}-add) the live lease set
// without racing the append-only memfile. The hook (libdhcp_lease_cmds.so)
// ships in kea-common; it is additive and does not change DHCP serving
// behavior.
func (m *Manager) addLeaseSyncStanza(dhcp map[string]any, family int) {
	if !m.leaseSyncEnabled.Load() {
		return
	}
	dhcp["control-socket"] = map[string]any{
		"socket-type": "unix",
		"socket-name": m.controlSocket(family),
	}
	dhcp["hooks-libraries"] = []map[string]any{
		{"library": libDHCPLeaseCmdsPath},
	}
}

func (m *Manager) writeKeaConfig(path string, keaCfg map[string]any) error {
	data, err := json.MarshalIndent(keaCfg, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	// AtomicGeneratedConfig (#1894): regenerated on apply; Kea must
	// never parse a torn file, but the apply path pays no fsync.
	return fsatomic.WriteFileAtomic(path, data, 0644)
}
