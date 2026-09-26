package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"sort"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ra"
)

// reconcileClusterRAServices converges the cluster RA senders to the union of
// buildRAConfigs filtered to the RGs this node is the CURRENT active owner for
// (#5861). It is the single authoritative cluster RA applier: every RA-affecting
// cluster event — a day-2 config commit, a VRRP MASTER/BACKUP transition, and
// the periodic dropped-event safety pass in reconcileRGState — funnels through
// it. Standalone (non-cluster) mode is a no-op here; that path applies RA
// directly in applyServicesReconcile.
//
// The pre-#5861 bug: a config commit in cluster mode SKIPPED ra.Apply (RA was
// managed only by ownership events) and the reconcile loop re-applied RA only
// on an rg_active transition (`if tr.Changed`). So a day-2 RA edit (add/remove
// prefix, change DNS/MTU/lifetime) on an RG that stayed MASTER never reached
// ra.Apply and the primary kept advertising the OLD set until failover/restart.
//
// Owner gating + demotion-race guard: the desired set is built from
// snapshotRethMasterState() — an RG's interfaces are included ONLY while this
// node is its active owner. The ownership snapshot and the ra.Apply run under
// raReconcileMu. Inactive interfaces using the shared stable RETH source are
// silently stopped before Apply, because their router identity may already be
// live on the peer; unique-source withdrawals keep the graceful goodbye. The
// VRRP demote path updates rg-state before it calls this function, so a config
// apply racing demotion either snapshots the RG inactive and silently stops it,
// or snapshots it active and the serialized demote pass stops it immediately
// afterward.
//
// Idempotence: a stable digest of the desired set (lastRAReconcileHash) gates
// the actual ra.Apply, so the periodic safety pass is free when nothing moved.
// The digest is updated only on a successful apply, so a transient apply error
// is retried on the next pass rather than being latched as converged.
func (d *Daemon) reconcileClusterRAServices(reason string) {
	d.raReconcileMu.Lock()
	defer d.raReconcileMu.Unlock()

	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		// Standalone mode owns RA directly in applyServicesReconcile.
		return
	}

	apply := d.raApplyFn
	if apply == nil {
		if d.ra == nil {
			return
		}
		apply = d.ra.Apply
	}

	desired, silentStop := d.clusterRAConfigSets(cfg)
	if err := d.clearInactiveSharedRASenders(silentStop); err != nil {
		slog.Warn("ra: shared-identity silent stop failed; will retry",
			"reason", reason, "err", err)
		return
	}
	newHash := raDesiredHash(desired)
	// #6793: a DEAD sender (its asynchronous conn open failed, so it will never
	// emit an RA) does not move the desired-set digest, so the idempotence gate
	// below skipped the very apply that would rebuild it. That made this
	// function's own "a transient apply error is retried on the next pass"
	// promise false for the one failure it cannot see in the digest: the
	// interface stayed silent until an unrelated config change moved the hash.
	// Re-drive the apply while any sender is dead; ra.Apply's #2865 branch does
	// the rebuild and is a no-op for every healthy sender in the same set.
	if newHash == d.lastRAReconcileHash && !d.raHasDeadSenders() {
		return
	}

	if err := apply(desired); err != nil {
		slog.Warn("ra: cluster RA reconcile failed; will retry",
			"reason", reason, "err", err)
		return
	}
	if len(desired) > 0 {
		slog.Info("ra: cluster RA reconciled to current active owners",
			"reason", reason, "interfaces", len(desired))
	} else if d.lastRAReconcileHash != "" {
		slog.Info("ra: cluster RA withdrawn (no active owner)", "reason", reason)
	}
	d.lastRAReconcileHash = newHash
}

// raHasDeadSenders reports whether the RA manager holds a sender whose
// asynchronous conn open failed (#6793). Routed through a daemon method rather
// than touching d.ra directly at the call sites so the nil-manager case (no RA
// configured, or a test daemon) is handled once.
func (d *Daemon) raHasDeadSenders() bool {
	if d.raHasDeadSendersFn != nil {
		return d.raHasDeadSendersFn()
	}
	return d.ra != nil && d.ra.HasDeadSenders()
}

// raDeadSenderReassertInterval is the cadence of the always-on dead-sender
// re-drive (#6793). A dead sender means an interface is advertising nothing, so
// the recovery wants to be prompt; but the repair is a full RA apply, so it must
// not run at the 2s cadence of the cluster reconcile. 30s matches
// proxyARPReassertInterval, the other always-on self-heal loop, and bounds the
// silent window to well inside a Router Lifetime.
var raDeadSenderReassertInterval = 30 * time.Second

// raDeadSenderReassertLoop is the retry owner a dead RA sender did not have
// (#6793). It covers the STANDALONE gap specifically: standalone applies RA
// from applyServicesReconcile, which runs only on a config apply, and
// reconcileRGStateLoop is cluster-only — so before this loop a boot-time bind
// failure left the interface with no router advertisements until an operator
// happened to commit. Hosts on that segment got no default route, on a node
// that had reported a successful commit.
//
// Always-on and mode-agnostic, mirroring proxyARPReassertLoop: it re-reads the
// active config each tick rather than capturing one at start, and it is free on
// the common path because the gate is a map walk over live senders. Cluster mode
// is additionally covered at its own 2s reconcile (the digest bypass above); this
// loop is harmless there — a pass with no dead sender does nothing at all.
func (d *Daemon) raDeadSenderReassertLoop(ctx context.Context) {
	t := time.NewTicker(raDeadSenderReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertDeadRASendersOnce(ctx)
		}
	}
}

// reassertDeadRASendersOnce re-drives one RA apply if — and only if — a sender
// is dead.
//
// It takes applySem before reading ActiveConfig, for the reason #4001 gave the
// proxy-ARP loop: reading the config outside the semaphore lets a tick capture a
// PRE-commit snapshot and re-assert state a concurrent commit has just removed.
// Here that would re-arm RA on an interface the operator had just deleted it
// from. Taking the semaphore makes the tick block behind any in-flight commit
// and always reconcile the post-commit config.
//
// The dead-sender check is deliberately re-run INSIDE the semaphore. The
// pre-check outside it is only an optimisation to avoid queueing behind a
// commit for nothing; a commit that lands in between may already have rebuilt
// the sender, and re-applying then would be a gratuitous RA restart.
func (d *Daemon) reassertDeadRASendersOnce(ctx context.Context) {
	// The applier seam, not d.ra.Apply directly: reconcileClusterRAServices
	// already selects through raApplyFn, and two RA appliers in one daemon is
	// the divergence this file exists to avoid. It also makes the re-drive
	// OBSERVABLE — without it the standalone half of the retry owner has no
	// assertion point that does not require a genuinely failing ndp.Listen.
	apply := d.raApplyFn
	if apply == nil {
		if d.ra == nil {
			return
		}
		apply = d.ra.Apply
	}
	if !d.raHasDeadSenders() {
		return
	}
	if d.applySem == nil {
		return
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return
	}
	defer d.applySem.Release(1)
	if !d.raHasDeadSenders() {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	var dead []string
	if d.ra != nil {
		dead = d.ra.DeadSenderInterfaces()
	}
	if cfg.Chassis.Cluster != nil {
		// Cluster mode owns RA through the digest-gated reconcile; drive THAT
		// rather than applying a standalone desired set here, or the two owners
		// would disagree about which RGs this node advertises for.
		slog.Info("ra: re-driving the cluster reconcile for a dead sender",
			"interfaces", dead)
		d.reconcileClusterRAServices("dead-sender-reassert")
		return
	}
	raConfigs := d.buildRAConfigs(cfg)
	if len(raConfigs) == 0 {
		return
	}
	slog.Info("ra: rebuilding a sender whose conn open failed",
		"interfaces", dead)
	if err := apply(raConfigs); err != nil {
		slog.Warn("ra: dead-sender rebuild failed; will retry",
			"interfaces", dead, "err", err)
	}
}

// desiredClusterRA returns the union of buildRAConfigs entries whose interface
// belongs to an RG this node is currently the active owner for. The union is
// sorted by interface name so the digest is stable across map-iteration order
// (snapshotRethMasterState and rethInterfacesForRG both iterate maps). Callers
// must hold raReconcileMu.
func (d *Daemon) desiredClusterRA(cfg *config.Config) []*config.RAInterfaceConfig {
	desired, _ := d.clusterRAConfigSets(cfg)
	return desired
}

// clusterRAConfigSets derives the active desired set and the inactive shared-
// identity interfaces that must be stopped silently. A stable RETH link-local is
// the cluster's router identity, not a node's: sending a demotion goodbye would
// also withdraw the peer's live default route. If both nodes are BACKUP, the
// stale route may persist until Router Lifetime expiry; a later MASTER's RA
// refresh repairs it.
func (d *Daemon) clusterRAConfigSets(cfg *config.Config) ([]*config.RAInterfaceConfig, []string) {
	masters := d.snapshotRethMasterState()
	ownedIfaces := make(map[string]bool)
	inactiveIfaces := make(map[string]bool)
	for _, name := range rethInterfacesMatchingRG(cfg, func(rgID int) bool { return masters[rgID] }) {
		ownedIfaces[name] = true
	}
	for _, name := range rethInterfacesMatchingRG(cfg, func(rgID int) bool { return !masters[rgID] }) {
		inactiveIfaces[name] = true
	}
	if len(ownedIfaces) == 0 && len(inactiveIfaces) == 0 {
		return nil, nil
	}

	var desired []*config.RAInterfaceConfig
	for _, cfgRA := range d.buildRAConfigs(cfg) {
		if ownedIfaces[cfgRA.Interface] {
			desired = append(desired, cfgRA)
		}
	}

	// Use the live sender source rather than current RA config: a config
	// removal racing demotion leaves the old sender active until this reconcile
	// applies. This also keeps periodic safety reconciles on the same silent-stop
	// path as the VRRP demotion edge.
	var silentStop []string
	for _, sender := range d.raSenderStatuses() {
		if sender.State == "active" &&
			inactiveIfaces[sender.Interface] &&
			!ownedIfaces[sender.Interface] &&
			isSharedStableRASource(sender.SrcAddr) {
			silentStop = append(silentStop, sender.Interface)
		}
	}
	sort.Slice(desired, func(i, j int) bool {
		return desired[i].Interface < desired[j].Interface
	})
	for _, cfgRA := range desired {
		sortRAPrefixes(cfgRA.Prefixes)
	}
	sort.Strings(silentStop)
	return desired, silentStop
}

func (d *Daemon) clearInactiveSharedRASenders(names []string) error {
	if len(names) == 0 {
		return nil
	}
	clear := d.raClearInterfacesFn
	if clear == nil {
		if d.ra == nil {
			return nil
		}
		clear = d.ra.ClearInterfacesWithoutGoodbye
	}
	return clear(names)
}

func (d *Daemon) raSenderStatuses() []ra.SenderInfo {
	if d.raStatusFn != nil {
		return d.raStatusFn()
	}
	if d.ra == nil {
		return nil
	}
	return d.ra.Status()
}

func isSharedStableRASource(source string) bool {
	return cluster.IsStableRethLinkLocal(net.ParseIP(source))
}

// sortRAPrefixes orders an RA interface's advertised prefixes by a stable, total
// key so the desired-set digest and ra.configEqual observe a deterministic order
// regardless of the source (map-iteration) order. nil entries sort last so a
// slice carrying a nil placeholder still has a total order. Callers must own the
// slice (see desiredClusterRA's in-place-sort safety note).
func sortRAPrefixes(prefixes []*config.RAPrefix) {
	sort.SliceStable(prefixes, func(i, j int) bool {
		a, b := prefixes[i], prefixes[j]
		if a == nil || b == nil {
			// Non-nil before nil; two nils compare equal (stable keeps order).
			return a != nil && b == nil
		}
		if a.Prefix != b.Prefix {
			return a.Prefix < b.Prefix
		}
		if a.ValidLifetime != b.ValidLifetime {
			return a.ValidLifetime < b.ValidLifetime
		}
		if a.PreferredLife != b.PreferredLife {
			return a.PreferredLife < b.PreferredLife
		}
		if a.OnLink != b.OnLink {
			return !a.OnLink // false sorts before true
		}
		return !a.Autonomous && b.Autonomous
	})
}

// raDesiredHash returns a stable digest of the desired RA set. An empty set
// hashes to "" so a pure-backup node (no active owner) matches the zero-value
// lastRAReconcileHash and never issues a spurious withdraw. A non-empty set
// hashes to a 64-char hex digest, which can never collide with "".
func raDesiredHash(desired []*config.RAInterfaceConfig) string {
	if len(desired) == 0 {
		return ""
	}
	b, err := json.Marshal(desired)
	if err != nil {
		// Marshal of exported-field structs cannot fail in practice; fall back
		// to a value that forces an apply rather than a false cache hit.
		return "unhashable"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
