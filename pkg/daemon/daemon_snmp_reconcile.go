package daemon

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/snmp"
)

// snmpBindTimeout bounds how long startSNMPLocked waits for the listener
// goroutine to confirm it bound UDP/161 before treating the start as failed.
// The real bind (ResolveUDPAddr + ListenUDP) is a synchronous syscall that
// reports in microseconds, so this ceiling only fires if a serve seam wedges;
// it exists solely to keep the apply path — which holds snmpReconMu — from
// blocking forever on a misbehaving listener.
const snmpBindTimeout = 5 * time.Second

// snmpEnabled reports whether the committed config asks for a running SNMP
// agent. It is the SINGLE source of truth shared by the boot start block
// (daemon_run.go) and the day-2 reconcile (reconcileSNMP) so the two can never
// diverge on what "SNMP is on" means: an SNMP stanza with at least one
// community or v3 user, and the snmpd process not administratively disabled.
func snmpEnabled(cfg *config.Config) bool {
	if cfg == nil || cfg.System.SNMP == nil {
		return false
	}
	s := cfg.System.SNMP
	if len(s.Communities) == 0 && len(s.V3Users) == 0 {
		return false
	}
	return !isProcessDisabled(cfg, "snmpd")
}

// snmpConfigHash is a deterministic fingerprint of the live SNMP stanza used as
// the reconcile idempotence gate: an unchanged stanza hashes equal, so a commit
// that does not touch SNMP is a true no-op (no listener bounce, no in-place
// swap). It hashes the RAW secret-bearing fields (community strings, v3
// passwords) directly rather than the redacting MarshalJSON surface, so a
// community rename or a password rotation is detected as a change. Maps are
// walked in sorted-key order so the hash is stable across map iteration order.
func snmpConfigHash(cfg *config.Config) uint64 {
	h := fnv.New64a()
	if cfg == nil || cfg.System.SNMP == nil {
		return h.Sum64()
	}
	s := cfg.System.SNMP
	write := func(str string) {
		var l [8]byte
		binary.LittleEndian.PutUint64(l[:], uint64(len(str)))
		_, _ = h.Write(l[:])
		_, _ = h.Write([]byte(str))
	}
	write(s.Location)
	write(s.Contact)
	write(s.Description)

	commNames := make([]string, 0, len(s.Communities))
	for name := range s.Communities {
		commNames = append(commNames, name)
	}
	sort.Strings(commNames)
	write("communities")
	for _, name := range commNames {
		c := s.Communities[name]
		write(name)
		if c != nil {
			write(c.Authorization)
			// #5105: the community `clients` source-IP allowlist and its
			// per-entry `restrict` (deny) bit are live authorization inputs
			// enforced by SNMPCommunity.AllowsSource. A day-2 edit that changes
			// ONLY the allowlist (same name + authorization) must NOT hash
			// equal, or reconcile takes the idempotent no-op path and the
			// running agent keeps the stale (possibly allow-all) source policy
			// while the commit reports success. Hash the allowlist in DOCUMENT
			// order (not sorted): AllowsSource resolves an equal-length prefix
			// tie as deny-wins (order-independent, #5523 C179-049), so element
			// order is NOT authorization-significant. Hashing in document order
			// is nonetheless retained as a CONSERVATIVE superset: it may
			// spuriously reconcile on an order-only reshuffle of two
			// contradictory equal-length prefixes, but it never MISSES a real
			// authorization change. Identical config text yields identical
			// order, so an unchanged stanza still hashes equal (no spurious
			// reconcile).
			write("clients")
			for _, cl := range c.Clients {
				write(cl.Prefix)
				if cl.Restrict {
					write("restrict")
				} else {
					write("allow")
				}
			}
			// #9416: the authored `client-list-name` references, and this is
			// NOT redundant with the resolved Clients above.
			//
			// A community whose ONLY restriction is an UNRESOLVABLE reference
			// has an EMPTY Clients — the referenced list does not exist, or is
			// empty — and is quarantined to deny-all through clientNets, which
			// this hash cannot see (the #5833 quarantine deliberately overrides
			// only the derived cache, never the config surface). So without
			// this line, adding such a reference to a previously-unrestricted
			// community hashes EQUAL, the reconcile takes the idempotent no-op
			// path, and the running agent keeps serving every source while the
			// commit reports success. That is exactly the #5105 class this
			// block exists to close, reached through a new door.
			//
			// Document order, de-duplicated by the compiler, for the same
			// reason the allowlist above is hashed in document order: it is a
			// conservative superset that can reconcile spuriously on a
			// reshuffle but can never MISS an authorization change.
			write("client-list-names")
			for _, ref := range c.ClientListNames {
				write(ref)
			}
		}
	}

	tgNames := make([]string, 0, len(s.TrapGroups))
	for name := range s.TrapGroups {
		tgNames = append(tgNames, name)
	}
	sort.Strings(tgNames)
	write("trap-groups")
	for _, name := range tgNames {
		tg := s.TrapGroups[name]
		write(name)
		if tg != nil {
			write(tg.Version)
			targets := append([]string(nil), tg.Targets...)
			sort.Strings(targets)
			for _, t := range targets {
				write(t)
			}
			// #5522: the trap-group `categories` filter is a live dispatch
			// input enforced by pkg/snmp groupWantsCategory. A day-2 edit that
			// changes ONLY the category scope (same name + version + targets)
			// must NOT hash equal, or reconcile takes the idempotent no-op path
			// and the running agent keeps sending traps in the removed category
			// while the commit reports success. Sort so a reordered-but-
			// equivalent list still hashes equal (dispatch is set membership,
			// order-insensitive).
			write("categories")
			cats := append([]string(nil), tg.Categories...)
			sort.Strings(cats)
			for _, c := range cats {
				write(c)
			}
		}
	}

	userNames := make([]string, 0, len(s.V3Users))
	for name := range s.V3Users {
		userNames = append(userNames, name)
	}
	sort.Strings(userNames)
	write("v3-users")
	for _, name := range userNames {
		u := s.V3Users[name]
		write(name)
		if u != nil {
			write(u.AuthProtocol)
			write(string(u.AuthPassword))
			write(u.PrivProtocol)
			write(string(u.PrivPassword))
		}
	}
	return h.Sum64()
}

// snmpLinkLister enumerates the kernel links buildSNMPIfData turns into the
// SNMP ifTable. It is a package-level seam (defaulting to netlink.LinkList) so a
// test can drive the netlink-failure path — a live RTM_GETLINK dump cannot be
// forced to fail from a unit test — and assert the failure is surfaced rather
// than silently reported as an empty ifTable (#5523 C179-123).
var snmpLinkLister = netlink.LinkList

// snmpIfDataWarnInterval bounds how often buildSNMPIfData emits its
// netlink-failure warning. buildSNMPIfData runs once per SNMP poll and a
// manager may poll several times a second, so a persistently failing
// RTM_GETLINK dump would otherwise write one warning line per poll and drown
// the journal (#6396 C179-123 residual).
const snmpIfDataWarnInterval = time.Minute

// snmpIfDataFailThrottle rate-limits buildSNMPIfData's netlink-failure warning.
var snmpIfDataFailThrottle warnThrottle

// warnThrottle emits at most one log per interval for a repeating condition,
// counting how many occurrences it suppressed between emitted logs. It is safe
// for concurrent use. The zero value is ready: the first occurrence always
// emits.
type warnThrottle struct {
	mu         sync.Mutex
	logged     bool // an emit has happened and no reset since
	lastLog    time.Time
	suppressed int
}

// shouldLog reports whether the caller should emit its warning for an
// occurrence at now, and how many prior occurrences were suppressed since the
// last emitted log. It emits on the first occurrence and then at most once per
// interval; occurrences inside the window are counted and suppressed.
func (t *warnThrottle) shouldLog(now time.Time, interval time.Duration) (emit bool, suppressed int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.logged || now.Sub(t.lastLog) >= interval {
		suppressed = t.suppressed
		t.suppressed = 0
		t.lastLog = now
		t.logged = true
		return true, suppressed
	}
	t.suppressed++
	return false, 0
}

// reset clears the throttle after the condition clears (e.g. a successful
// read), so the next occurrence logs immediately. It reports whether the
// condition had been active and how many occurrences were suppressed since the
// last emitted log, so the caller can note a recovery exactly once.
func (t *warnThrottle) reset() (wasActive bool, suppressed int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	wasActive = t.logged
	suppressed = t.suppressed
	t.logged = false
	t.suppressed = 0
	t.lastLog = time.Time{}
	return wasActive, suppressed
}

// buildSNMPIfData returns the live interface table for the SNMP ifTable /
// ifXTable, read from netlink at call time. It is the SetIfDataFn callback
// wired onto every agent the daemon starts (both the boot start and a day-2
// reconcile start), so the agent always reports the current kernel interface
// state regardless of when it was started (#3967 extracted this from the boot
// block so the two start paths share one implementation).
func buildSNMPIfData() []snmp.IfData {
	links, err := snmpLinkLister()
	if err != nil {
		// #5523 C179-123: a transient netlink failure must NOT masquerade as a
		// healthy 0-interface ifTable. The SetIfDataFn callback contract
		// (func() []snmp.IfData) has no error channel, so an empty slice is the
		// only value we can hand back — but returning it SILENTLY let a manager
		// read the box as having no interfaces while the poll still looked
		// successful. Log the failure so the empty table is diagnosable and
		// distinguishable from a genuine no-interface box; the next poll
		// re-reads netlink and self-heals a transient error.
		//
		// #6396: the warning is rate-limited (snmpIfDataWarnInterval) so a
		// PERSISTENT failure — buildSNMPIfData runs once per poll, and a manager
		// may poll several times a second — logs once per window instead of one
		// line per poll. The first failure always logs; subsequent ones inside
		// the window are counted and reported with the next emitted line.
		if emit, suppressed := snmpIfDataFailThrottle.shouldLog(time.Now(), snmpIfDataWarnInterval); emit {
			slog.Warn("SNMP ifTable read failed; reporting empty interface table",
				"err", err, "suppressed_since_last", suppressed)
		}
		return nil
	}
	// A successful read clears the throttle so a later failure logs promptly
	// again; note the recovery once if the table had been failing (#6396).
	if wasActive, suppressed := snmpIfDataFailThrottle.reset(); wasActive {
		slog.Info("SNMP ifTable read recovered",
			"suppressed_failures", suppressed)
	}
	var result []snmp.IfData
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Name == "lo" {
			continue
		}
		ifType := 6 // ethernetCsmacd
		switch link.Type() {
		case "vrf":
			ifType = 53 // propVirtual
		case "gre", "ip6tnl", "xfrm":
			ifType = 131 // tunnel
		case "veth":
			ifType = 53
		}
		admin := 2 // down
		if attrs.Flags&net.FlagUp != 0 {
			admin = 1
		}
		oper := 2 // down
		if attrs.OperState == netlink.OperUp || attrs.OperState == netlink.OperUnknown {
			oper = 1
		}
		speed := uint32(0)
		if attrs.TxQLen > 0 {
			speed = 1000000000 // default 1Gbps
		}
		var stats *netlink.LinkStatistics
		if attrs.Statistics != nil {
			stats = attrs.Statistics
		}
		entry := snmp.IfData{
			IfIndex:     attrs.Index,
			IfDescr:     attrs.Name,
			IfType:      ifType,
			IfMtu:       attrs.MTU,
			IfSpeed:     speed,
			AdminStatus: admin,
			OperStatus:  oper,
			IfName:      attrs.Name,
			IfHighSpeed: speed / 1_000_000, // bps -> Mbps
		}
		if stats != nil {
			deriveIfCounters(&entry, stats)
		}
		result = append(result, entry)
	}
	return result
}

// deriveIfCounters fills the IF-MIB packet/octet counter fields of entry from
// the Linux rtnl_link_stats the kernel exposes through netlink. It is factored
// out of buildSNMPIfData as a pure seam so the class-counter semantics can be
// unit-tested without a live netlink socket (#5050).
//
// IF-MIB class semantics (RFC 2863): ifInUcastPkts / ifHCInUcastPkts count
// packets that were NOT addressed to a multicast or broadcast address, and the
// unicast / multicast / broadcast columns must not overlap. Linux
// rtnl_link_stats reports total RxPackets/TxPackets plus a single RX
// `multicast` sub-count; it exposes no RX broadcast count and no TX
// multicast/broadcast breakdown at all. Copying RxPackets/TxPackets straight
// into the unicast counters (the old behavior) folded multicast+broadcast into
// unicast, so a manager summing the class columns double-counted them.
func deriveIfCounters(entry *snmp.IfData, stats *netlink.LinkStatistics) {
	entry.InOctets = uint32(stats.RxBytes)
	entry.OutOctets = uint32(stats.TxBytes)
	entry.HCInOctets = stats.RxBytes
	entry.HCOutOctets = stats.TxBytes

	// IN unicast = RxPackets - Multicast: the one non-unicast RX subset the
	// kernel gives us. Clamp at 0 in case a racy stats read observes
	// Multicast > RxPackets (the two counters are not sampled atomically).
	inUcast := stats.RxPackets
	if stats.Multicast > inUcast {
		inUcast = 0
	} else {
		inUcast -= stats.Multicast
	}
	entry.HCInUcastPkts = inUcast

	// OUT unicast: rtnl_link_stats exposes no TX multicast/broadcast
	// breakdown, so an exact TX unicast count is unavailable. TxPackets is
	// an upper bound; the (typically negligible on a routed firewall) TX
	// non-unicast residual cannot be separated and is not subtracted. This
	// is a documented approximation, not a relabelled total for a counter we
	// could otherwise split.
	entry.HCOutUcastPkts = stats.TxPackets

	// ifInMulticastPkts is the only non-unicast class Linux exposes. The
	// broadcast columns and the TX class columns stay 0 because
	// rtnl_link_stats does not report them — an honest zero is better than
	// folding those packets into the unicast counter.
	entry.InMulticastPkts = uint32(stats.Multicast)
}

// reconcileSNMP reconciles the running SNMP subsystem against the committed
// config on every apply (#3967). Before this, the agent + trap-group monitor
// were started ONCE at boot; a day-2 commit that enabled SNMP, added a
// community/trap target, or disabled SNMP sat inert in the config until a
// daemon restart. reconcileSNMP closes that gap by matching the live subsystem
// to the config on each commit:
//
//   - disabled -> enabled: create and start the agent listener (and the
//     link-state trap monitor if trap groups are configured).
//   - enabled  -> disabled: stop the listener and the monitor.
//   - enabled  -> enabled (config changed): swap the live authorization /
//     community / trap-target set in place via UpdateConfig (no listener
//     bounce — the UDP socket and in-flight polls are preserved), and start
//     the link-state monitor if trap groups appeared and it is not yet running.
//   - enabled  -> enabled (unchanged): no-op (idempotence gate on snmpConfigHash).
//
// It returns true when it changed the running subsystem. It runs BEFORE the
// dataplane apply in applyConfigLocked, mirroring the pre-#3967 UpdateConfig
// placement, so a committed change reaches the agent even on an apply that
// aborts early on a dataplane protocol-gate error.
//
// The START path requires d.snmpBootReady (set after the boot block) and
// d.daemonCtx. During the boot apply, snmpBootReady is still false so this
// no-ops the start and the boot block owns the first start (which respects
// config-only / bootstrap suppression). The UpdateConfig and disable paths do
// not depend on snmpBootReady, so an agent that IS running is always reconciled.
func (d *Daemon) reconcileSNMP(cfg *config.Config) bool {
	d.snmpReconMu.Lock()
	defer d.snmpReconMu.Unlock()

	desired := snmpEnabled(cfg)

	// Disable path: stop a running agent; no-op when already stopped.
	if !desired {
		if d.snmpAgent == nil {
			return false
		}
		d.teardownSNMPLocked()
		d.snmpHash, d.snmpHashSet = 0, false
		slog.Info("SNMP agent stopped (configuration disabled)")
		return true
	}

	h := snmpConfigHash(cfg)

	// Enable path, no agent running: start it. Gated on the boot handoff so
	// the boot apply does not race the boot block into a double-start, and on
	// daemonCtx so we have a lifetime to bind the goroutines to.
	if d.snmpAgent == nil {
		if !d.snmpBootReady || d.daemonCtx == nil {
			return false
		}
		// Record the desired hash ONLY on a confirmed-listening agent. If the
		// bind failed (e.g. transient UDP/161 conflict), startSNMPLocked has
		// already torn the half-started agent down and returned the error;
		// leaving snmpHash/snmpHashSet unchanged keeps d.snmpAgent nil, so the
		// NEXT identical apply re-enters this branch and RETRIES the bind
		// (self-heals a transient failure) instead of silently no-oping (#5110).
		if err := d.startSNMPLocked(cfg); err != nil {
			slog.Warn("SNMP agent start failed; leaving desired hash unrecorded so the next apply retries the bind",
				"err", err)
			return false
		}
		d.snmpHash, d.snmpHashSet = h, true
		return true
	}

	// Agent already running: idempotent no-op when the stanza is unchanged.
	if d.snmpHashSet && h == d.snmpHash {
		return false
	}

	// Live in-place reconcile: swap authorization / community / trap targets
	// without dropping the UDP listener.
	d.snmpAgent.UpdateConfig(cfg.System.SNMP)

	// Bring up the link-state trap monitor if trap groups appeared after the
	// agent started (the boot start only launches the monitor when trap groups
	// exist at boot). Requires daemonCtx (present whenever the agent is
	// running via the normal paths).
	if len(cfg.System.SNMP.TrapGroups) > 0 && !d.snmpMonitorRunning && d.snmpCtx != nil {
		d.startSNMPMonitorLocked()
	}

	d.snmpHash, d.snmpHashSet = h, true
	slog.Info("SNMP agent configuration reconciled")
	return true
}

// startSNMPLocked creates the SNMP agent for cfg and starts its UDP/161
// listener (and the link-state trap monitor when trap groups are configured)
// on a fresh lifetime context derived from d.daemonCtx. The caller MUST hold
// snmpReconMu and MUST have verified snmpEnabled(cfg). Shared by the boot start
// block and reconcileSNMP so both go through one implementation (#3967).
//
// It waits (bounded by snmpBindTimeout) for the listener goroutine to confirm
// it actually bound the socket before returning, and returns a non-nil error if
// the bind FAILED (or timed out). On that error path it has already rolled the
// half-started agent back via teardownSNMPLocked — no goroutine or socket is
// left behind and d.snmpAgent is nil again — so the caller must NOT publish the
// running-config hash and a later identical apply can retry a clean start. This
// closes #5110: the pre-fix serve closure discarded Agent.Start's bind error,
// so a transient UDP/161 failure left SNMP absent while the desired hash still
// recorded "applied", no-oping every subsequent identical commit.
func (d *Daemon) startSNMPLocked(cfg *config.Config) error {
	ctx, cancel := context.WithCancel(d.daemonCtx)
	agent := snmp.NewAgentWithPaths(cfg.System.SNMP, d.snmpBootsPath, d.snmpEngineIDPath)
	// Host-inbound SNMP is served from the management routing context; a
	// wildcard UDP socket otherwise replies and emits traps through main.
	agent.SetVRFDevice(config.ManagementVRFDeviceName)

	// The serve seam binds UDP/161 and then serves for the lifetime of ctx. It
	// reports the bind outcome on `ready` EXACTLY ONCE — nil once the listener
	// is bound (before entering the blocking serve loop), or the bind error if
	// it failed — so startSNMPLocked can gate hash publication on a real bind.
	// The default splits Agent.Bind (synchronous bind) from Agent.Serve (the
	// blocking loop); tests inject a seam that scripts the bind outcome without
	// touching a privileged socket.
	serve := d.snmpServe
	if serve == nil {
		serve = func(ctx context.Context, a *snmp.Agent, ready chan<- error) {
			if err := a.Bind(ctx); err != nil {
				ready <- err
				return
			}
			ready <- nil
			a.Serve()
		}
	}

	wg := &sync.WaitGroup{}
	d.snmpAgent = agent
	d.snmpCtx = ctx
	d.snmpCancel = cancel
	d.snmpWg = wg
	d.snmpMonitorRunning = false

	// Buffered so the listener goroutine never blocks on the send even if we
	// stopped waiting (timeout path) before it reported.
	ready := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		serve(ctx, agent, ready)
	}()

	var bindErr error
	select {
	case bindErr = <-ready:
	case <-time.After(snmpBindTimeout):
		bindErr = fmt.Errorf("snmp: listener did not confirm bind within %s", snmpBindTimeout)
	}
	if bindErr != nil {
		// Roll the partially-started agent back so the failure path leaks no
		// goroutine/socket and the next identical apply retries a clean start.
		d.teardownSNMPLocked()
		return bindErr
	}

	if len(cfg.System.SNMP.TrapGroups) > 0 {
		d.startSNMPMonitorLocked()
	}
	slog.Info("SNMP agent started",
		"communities", len(cfg.System.SNMP.Communities),
		"v3_users", len(cfg.System.SNMP.V3Users),
		"trap_groups", len(cfg.System.SNMP.TrapGroups))
	return nil
}

// startSNMPMonitorLocked launches the netlink link-state trap monitor on the
// agent's lifetime context. The caller MUST hold snmpReconMu, MUST have a
// running agent (d.snmpAgent != nil, d.snmpCtx != nil), and MUST check
// d.snmpMonitorRunning first so the monitor is never started twice.
func (d *Daemon) startSNMPMonitorLocked() {
	d.snmpMonitorRunning = true
	d.snmpWg.Add(1)
	go func() {
		defer d.snmpWg.Done()
		d.monitorLinkState(d.snmpCtx)
	}()
}

// teardownSNMPLocked cancels the agent's lifetime context, joins the listener
// and monitor goroutines, closes the UDP socket, and clears the per-agent
// handles. The caller MUST hold snmpReconMu. Joining before nilling d.snmpAgent
// establishes a happens-before edge so the monitor goroutine's reads of
// d.snmpAgent (emitLinkStateTrap) never race the clear. Nil-safe / idempotent.
func (d *Daemon) teardownSNMPLocked() {
	if d.snmpCancel != nil {
		d.snmpCancel()
	}
	if d.snmpWg != nil {
		d.snmpWg.Wait()
	}
	if d.snmpAgent != nil {
		d.snmpAgent.Stop()
	}
	d.snmpAgent = nil
	d.snmpCtx = nil
	d.snmpCancel = nil
	d.snmpWg = nil
	d.snmpMonitorRunning = false
}

// teardownSNMP stops the SNMP subsystem during daemon shutdown. The agent
// goroutines bind to d.daemonCtx (never cancelled in production), so an
// explicit teardown is needed to release UDP/161 and join the goroutines on
// stop. Nil-safe / idempotent.
func (d *Daemon) teardownSNMP() {
	d.snmpReconMu.Lock()
	defer d.snmpReconMu.Unlock()
	d.teardownSNMPLocked()
	d.snmpHash, d.snmpHashSet = 0, false
}
