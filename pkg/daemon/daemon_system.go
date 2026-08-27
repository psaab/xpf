// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/vishvananda/netlink"
)

// applySyslogConfig constructs syslog clients or local log writers from the
// config and applies them to the event reader. When mode is "event", events
// are written to a local file; when "stream" (default), events are forwarded
// to remote syslog servers. Also updates zone name resolution for structured logging.
func (d *Daemon) applySyslogConfig(er *logging.EventReader, cfg *config.Config) {
	if er == nil {
		return
	}
	// Update zone name map for structured syslog formatting
	zoneNames := make(map[uint16]string)
	zoneIDs := buildZoneIDs(cfg)
	for name, id := range zoneIDs {
		zoneNames[id] = name
	}
	er.SetZoneNames(zoneNames)

	// Wire policy names and app names for structured logging.
	// #2114: ONE cell load inside applyResult (LastApplyResultOf is
	// nil-safe) — a separate dataplane() guard here would observe a
	// different publication than the result read (Codex PR #6743 r3-7).
	if cr := d.applyResult(); cr != nil {
		er.SetPolicyNames(cr.PolicyNames)
		if cr.AppNames != nil {
			er.SetAppNames(cr.AppNames)
		}
	}

	// #6859: wire the (filter_id, term_id) -> `then syslog` map so the event
	// reader can keep a `then log` hit off the syslog clients, the way Junos
	// does. Derived from cfg through the SAME snapshot builder whose output is
	// pushed to the dataplane, so the ids agree with the ones the events carry.
	//
	// Set UNCONDITIONALLY on every apply, including a config with no filters
	// (an empty non-nil map): the empty case is exactly a config whose filters
	// were all removed, and leaving the previous map installed would keep
	// forwarding under a deleted term's spelling. Nil is reserved for "never
	// wired" and would restore the pre-#6859 fan-out.
	er.SetFilterTermSyslog(dpuserspace.FilterTermSyslogMap(cfg))

	// Wire interface names (ifindex -> name) from config
	ifNames := make(map[uint32]string)
	for name, iface := range cfg.Interfaces.Interfaces {
		ifName := name
		if iface != nil && iface.Name != "" {
			ifName = iface.Name
		}
		if link, err := netlink.LinkByName(ifName); err == nil {
			ifNames[uint32(link.Attrs().Index)] = ifName
		}
	}
	er.SetIfNames(ifNames)

	// Event mode: write to local file instead of remote syslog
	if cfg.Security.Log.Mode == "event" {
		er.ReplaceSyslogClients(nil) // close + clear any remote clients (#3579)
		lw, err := logging.NewLocalLogWriter(logging.LocalLogConfig{})
		if err != nil {
			slog.Warn("failed to create local log writer", "err", err)
		} else {
			if cfg.Security.Log.Format != "" {
				lw.Format = cfg.Security.Log.Format
			}
			er.ReplaceLocalWriters([]*logging.LocalLogWriter{lw})
			slog.Info("security log event mode: writing to /var/log/xpf/security.log",
				"format", cfg.Security.Log.Format)
		}
		d.applyAggregator(er, cfg)
		return
	}

	// Stream mode (default): clear local writers, set up remote syslog
	er.ReplaceLocalWriters(nil)

	if len(cfg.Security.Log.Streams) == 0 {
		// Tear down any clients a prior config installed: a day-2 commit that
		// removes ALL streams must not leave lingering clients forwarding to a
		// deleted destination. This matches the event-mode (line ~65) and
		// applySystemSyslog teardown paths, which already clear clients. It
		// matters most after #3351: a down-at-apply TCP/TLS stream is now an
		// installed RECONNECTING client, so without this it would resume
		// sending audit logs to a removed receiver once that receiver recovers.
		// ReplaceSyslogClients (not the non-closing SetSyslogClients) also
		// Closes the superseded clients' connections so a CONNECTED stream's
		// fd is not leaked when all streams are removed (#3579).
		er.ReplaceSyslogClients(nil)
		d.applyAggregator(er, cfg)
		return
	}
	// Resolve global source-interface to IP (fallback for streams without source-address).
	// Prefer PrimaryAddress from config if set on the source interface unit.
	var globalSourceAddr string
	if cfg.Security.Log.SourceInterface != "" {
		globalSourceAddr = config.ResolveSyslogSourceAddr(cfg, cfg.Security.Log.SourceInterface)
	}

	var clients []*logging.SyslogClient
	for name, stream := range cfg.Security.Log.Streams {
		// #6875 precedence: an explicitly configured address beats one derived
		// from an interface, and both beat the global fallback.
		//
		//	source-address  >  source-interface  >  global source-interface
		//
		// The per-stream source-interface arm is the new one. Before #6875 the
		// leaf parsed (the stream subtree is open-world), compiled to nothing,
		// and the stream silently sourced from globalSourceAddr or from
		// nothing at all.
		//
		// A source-interface that resolves to no address falls through to the
		// global rather than pinning the stream to "": resolution reads
		// interface state, so an interface that is merely not up yet must not
		// permanently strip a source the operator did configure globally.
		srcAddr := stream.SourceAddress
		if srcAddr == "" && stream.SourceInterface != "" {
			srcAddr = config.ResolveSyslogSourceAddr(cfg, stream.SourceInterface)
		}
		if srcAddr == "" {
			srcAddr = globalSourceAddr
		}
		protocol := stream.Transport.Protocol
		if protocol == "" {
			protocol = "udp"
		}
		// #3350: the final *tls.Config is nil — a TLS stream trusts the system
		// CA roots (pkg/logging/syslog.go dialTLS). A named `transport
		// tls-profile` is NOT honored here (there is no TLS profile definition
		// stanza to resolve into a cert/CA/SNI config); it is rejected at commit
		// by validateSecurityLogStreamTLSProfileAST so it can never silently
		// degrade the secure-syslog posture. If profile resolution is ever
		// implemented, build the *tls.Config from stream.Transport.TLSProfile
		// here and lift that compiler reject.
		// #6829 round 8: classify the facility BEFORE constructing the client.
		// Construction DIALS, and an unmappable facility is the one diagnosis
		// that does not depend on the network being up — the same reasoning
		// already written at the host site. Measured before this change: a
		// stream with `host 192.0.2.10` (TEST-NET, UDP construction returns
		// nil,err) was skipped by the `client == nil` continue below and the
		// operator was never told the facility was ALSO unmappable.
		//
		// SPLIT, not moved, and this is the load-bearing part. The old position
		// supplied something besides ordering: `client` is guaranteed non-nil
		// there precisely BECAUSE the nil case already `continue`d. Hoisting the
		// whole block would put `client.Facility` on a pointer that does not
		// exist yet. So only the COMPUTE half moves — it needs nothing from
		// client — and the ASSIGN half stays below the continue, keeping the
		// same guarantee from the same source.
		//
		// haveFacility preserves the original conditional assignment: a stream
		// with no facility must keep the constructor default rather than be
		// overwritten with a zero value.
		var facility int
		var haveFacility bool
		if stream.Facility != "" {
			// #6829 A2: use the CHECKED form and report the substitution. The
			// schema enum gates this on the STRICT path only —
			// configstore.Store downgrades the gate to a warning on Load (boot)
			// and SyncApply (HA peer sync), so an unmappable name reaches here
			// on exactly the tolerant paths the severity belt is built for.
			// Untold, every record on this stream leaves under local0 while
			// `show system syslog` still reports the authored name.
			f, known := logging.ParseFacilityChecked(stream.Facility)
			// #6829 B2: NO wildcard suppression on this surface. `any` is the
			// Junos "all facilities" spelling on the system-syslog
			// host/file/user surface, whose facility key is an OPEN-ENDED
			// schema wildcard — and this is not that surface. A security
			// stream's facility is ValidateEnum(syslogFacilities), which lists
			// auth/change-log/daemon/kern/local0-7/syslog/user and does NOT
			// include `any`; the stream carries a numeric facility, so there is
			// no wildcard for `any` to mean here.
			//
			// Suppressing on it therefore silenced the diagnostic on exactly
			// the population it was built for: `any` cannot arrive by strict
			// commit, so it arrives only via the TOLERANT paths
			// (configstore.Store's Load/SyncApply downgrade), and there it is
			// mapped to local0 with no warning at all — the silence this PR
			// exists to remove, reinstated by a helper borrowed from the other
			// surface.
			if !known {
				slog.Warn("security log: unmapped facility name; local0 selected — if this "+
					"stream's client is installed, its records will carry a facility the "+
					"configuration does not name (#5797)",
					"facility", stream.Facility, "using", "local0")
			}
			facility, haveFacility = f, true
		}
		client, err := logging.NewSyslogClientTransport(stream.Host, stream.Port, srcAddr, protocol, nil)
		if err != nil {
			if client == nil {
				// UDP / unrecoverable construction error: skip the stream.
				slog.Warn("failed to create syslog client",
					"stream", name, "host", stream.Host, "protocol", protocol, "err", err)
				continue
			}
			// #3351: a TCP/TLS receiver unreachable at apply returns a usable
			// but unconnected client. Install it in this reconnecting state so
			// audit logging resumes when the receiver comes back, instead of
			// silently dropping the stream for the life of this config.
			slog.Warn("syslog stream receiver unreachable at apply; installed in reconnecting state",
				"stream", name, "host", stream.Host, "protocol", protocol, "err", err)
		}
		if stream.Severity != "" {
			client.MinSeverity = logging.ParseSeverity(stream.Severity)
		}
		if haveFacility {
			// Assign half — see the classification block above the client
			// construction. This stays below the `client == nil` continue
			// because that continue is what makes the pointer safe here.
			client.Facility = facility
		}
		if stream.Category != "" {
			client.Categories = logging.ParseCategory(stream.Category)
		}
		// Per-stream format overrides global log format
		format := stream.Format
		if format == "" {
			format = cfg.Security.Log.Format
		}
		if format != "" {
			client.Format = format
		}
		slog.Info("syslog stream configured",
			"stream", name, "host", stream.Host, "port", stream.Port,
			"protocol", protocol, "severity", stream.Severity,
			"facility", stream.Facility, "format", format,
			"category", stream.Category)
		clients = append(clients, client)
	}
	// #3579: install the freshly-built client set AND close the superseded
	// set in one atomic swap. applySyslogConfig rebuilds every SyslogClient
	// from config on each apply (the loop above always constructs new
	// objects via NewSyslogClientTransport), so the prior set is ALWAYS fully
	// superseded by-object and every old client's connection must be closed —
	// otherwise a re-apply that changed or dropped a CONNECTED TCP/TLS stream
	// would leak the old socket (fd). ReplaceSyslogClients (the closing
	// variant the CLI apply path already uses, pkg/cli/apply.go) closes the
	// old set AFTER releasing syslogMu, and SyslogClient.Close only takes the
	// client's own mutex (no slog under it), so the close cannot re-enter the
	// slog->syslog handler path under a held lock (#2285). The prior
	// len(clients) > 0 guard is intentionally gone: when streams are
	// configured but none could be built (all UDP construction failures), the
	// old clients must still be torn down rather than left forwarding to a
	// stale destination.
	er.ReplaceSyslogClients(clients)
	d.applyAggregator(er, cfg)
}

// aggregationCallback is the single, stable session-aggregation handler
// registered on the EventReader exactly ONCE (aggCBOnce). It reads the live
// SessionAggregator lock-free from the atomic pointer, so a config commit can
// swap the aggregator — or clear it to nil on disable — without ever
// registering a second callback. This is the #4964 fix mirroring the #3932
// flow-trace / #2075 flow-export indirection: the previous applyAggregator
// called er.AddCallback on every report-enabled reconcile, so a long-lived
// daemon leaked one callback (and one never-flushed aggregator) per commit and
// dispatched every event to all of them. A nil pointer (reporting disabled)
// makes this a no-op.
func (d *Daemon) aggregationCallback(rec logging.EventRecord, raw []byte) {
	agg := d.aggregatorPtr.Load()
	if agg == nil {
		return
	}
	agg.HandleEvent(rec, raw)
}

// aggregatorSig is the comparable, derived-config signature of one aggregator
// generation. applyAggregator retires+rebuilds the running aggregator only when
// the signature genuinely changes (#5313). Only `enabled` is config-driven
// today — window/topN are fixed defaults — but folding them into the signature
// keeps the equality gate correct if either becomes configurable later.
type aggregatorSig struct {
	enabled       bool
	flushInterval time.Duration
	topN          int
}

// Fixed defaults for the session aggregation reporter. NewSessionAggregator(0,
// 0) resolves to these same values internally; naming them here lets the
// equality-gate signature carry the parameters the aggregator is built from.
const (
	aggregatorFlushInterval = 5 * time.Minute
	aggregatorTopN          = 10
)

// applyAggregator starts, stops, or LEAVES-RUNNING the session aggregation
// reporter. The stable indirection callback (aggregationCallback) is registered
// on er exactly once — the first time reporting is enabled — so N report-enabled
// commits leave exactly one registered callback and one live aggregator (#4964).
//
// #5313 (equality gate + final flush): the pre-#5313 body cancelled+replaced the
// aggregator on EVERY call with no equality check. Because aggregator.Run only
// flushed on ticker.C and returned on ctx.Done WITHOUT flushing, any unrelated
// report-enabled commit (a syslog-stream edit, a hostname change — anything that
// re-runs applySyslogConfig) tore down the running aggregator and silently
// discarded up to a full flush window (~5 min) of pending SESSION_CLOSE counters.
// Two composed fixes close that:
//
//  1. Equality gate: if a live aggregator's derived signature is unchanged, keep
//     it — and its pending window — running instead of cancel+replace.
//  2. Final flush: aggregator.Run now flushes the pending window on ctx.Done, so
//     a genuine replace/disable emits the retiring window as a partial report
//     (the new generation starts from an empty window — no double count) rather
//     than dropping it.
//
// Disabling reporting stores a nil aggregator; the stable callback stays but
// becomes a no-op.
func (d *Daemon) applyAggregator(er *logging.EventReader, cfg *config.Config) {
	d.aggReconMu.Lock()
	defer d.aggReconMu.Unlock()

	// #5523 C179-093: once stopAggregator has run at shutdown, a late commit
	// (e.g. a racing apply) must NOT start a new aggregator generation — that
	// aggWg.Add would race the shutdown join. Mirrors the pinRetryStopped /
	// schedulerStopped latches (#5308).
	if d.aggStopped {
		return
	}

	desired := aggregatorSig{
		enabled:       cfg.Security.Log.Report,
		flushInterval: aggregatorFlushInterval,
		topN:          aggregatorTopN,
	}

	// Equality gate (#5313): a live aggregator whose derived config is unchanged
	// keeps running — do NOT cancel+replace it, which would discard its pending
	// flush window. Only a genuine change (enable/disable or a parameter change)
	// falls through to teardown.
	if d.aggCancel != nil && d.aggSig == desired {
		return
	}

	// Retire the running aggregator generation (config genuinely changed, or we
	// are disabling). Swap the published pointer to nil FIRST so no in-flight
	// event can enter the retired aggregator via the stable callback, THEN cancel
	// its flush goroutine. Retiring in the other order would let HandleEvent keep
	// feeding a cancelled aggregator (the #4964 leak). Cancelling now triggers
	// Run's final flush (#5313): the retiring generation emits its pending window
	// as a partial report before returning, so those ~5 min of counters are not
	// silently dropped.
	if d.aggCancel != nil {
		d.aggregatorPtr.Store(nil)
		d.aggCancel()
		d.aggCancel = nil
		d.aggSig = aggregatorSig{}
	}

	if !desired.enabled {
		return
	}

	agg := logging.NewSessionAggregator(desired.flushInterval, desired.topN)

	// Wire aggregator log output to the first available syslog client or local writer
	agg.SetLogFunc(func(severity int, msg string) {
		er.ForwardLogMsg(severity, msg)
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Publish the new aggregator BEFORE arming the callback (and before Run
	// starts) so the stable callback, once registered, never observes a nil
	// during startup. Add accumulates immediately; Run only flushes.
	d.aggregatorPtr.Store(agg)
	d.aggCancel = cancel
	d.aggSig = desired

	// Register the single stable callback exactly once, the first time
	// reporting is enabled. A boot with reporting disabled registers nothing;
	// the first enable arms it. er is the same EventReader across every commit
	// (daemon_run.go assigns the boot reader to d.eventReader, daemon_apply.go
	// passes d.eventReader), so one registration covers all generations.
	d.aggCBOnce.Do(func() {
		er.AddCallback(d.aggregationCallback)
	})

	// Track the flush goroutine on aggWg so stopAggregator can JOIN it at
	// shutdown (#5523 C179-093). A retired generation (cancel+replace above)
	// stays tracked until its ctx.Done final flush returns, so the shutdown join
	// covers both the live generation and any still-flushing retired one.
	d.aggWg.Add(1)
	go func() {
		defer d.aggWg.Done()
		agg.Run(ctx)
	}()
	slog.Info("session aggregation reporting enabled (5 min interval)")
}

// aggregatorFlushJoinTimeout bounds how long stopAggregator waits for the
// session-aggregation final flush to complete before proceeding to teardown
// (#6395). The cancel below triggers SessionAggregator.Run's #5313 ctx.Done
// final flush, which forwards the pending report SYNCHRONOUSLY through the
// syslog client (logFn -> er.ForwardLogMsg); a stream-syslog sink allows up to
// defaultWriteTimeout (~4s) PER line (pkg/logging/syslog.go), so a stalled or
// unreachable collector could otherwise block this join for many seconds. Since
// stopAggregator runs BEFORE the HA takeover fence in runShutdownSequence, an
// unbounded wait can push the whole stop past the systemd 20s TimeoutStopSec
// (test/incus/xpfd.service) and get the process SIGKILLed before the peer
// takeover fence runs. 3s is comfortably under a single write timeout and well
// under both the #5643 applyCloseoutDrainTimeout (5s) and the fence's share of
// the stop budget, so a stalled sink can never starve the fence.
const aggregatorFlushJoinTimeout = 3 * time.Second

// stopAggregator cancels the live session-aggregation generation and JOINS its
// flush goroutine (and any still-flushing retired generation) at shutdown. The
// cancel triggers SessionAggregator.Run's #5313 ctx.Done final flush, so the
// pending ~5 min window is emitted as a partial report instead of being dropped
// when the daemon stops. It latches aggStopped so a late applyAggregator cannot
// start a new generation after the join. Idempotent / nil-safe: with reporting
// never enabled there is no cancel and the WaitGroup is empty.
//
// The join is BOUNDED by aggregatorFlushJoinTimeout (#6395): the final flush
// forwards synchronously through the syslog client, so a stalled/unreachable
// sink would otherwise block this wait — which precedes the HA takeover fence —
// long enough to blow the systemd stop budget and get SIGKILLed before the
// fence runs. On the happy path the flush completes in milliseconds and the
// select returns immediately; on a stalled sink we log a warning and PROCEED to
// teardown, dropping the partial report (the acceptable fallback — a missed
// fence is worse). The join goroutine is left to finish late: the process is
// exiting, so leaking the flush's remaining lifetime is harmless.
//
// aggReconMu is held only to latch the flag and read+clear the handles, then
// RELEASED before the join: SessionAggregator.Run does not take aggReconMu, so
// releasing avoids holding the commit-path lock across the flush. Called from
// runShutdownSequence BEFORE the syslog/event teardown so the final flush still
// has a live forwarding path (SetLogFunc -> er.ForwardLogMsg). Mirrors the
// #5308 stopPinRetryLoop shape.
func (d *Daemon) stopAggregator() {
	d.aggReconMu.Lock()
	d.aggStopped = true
	cancel := d.aggCancel
	d.aggCancel = nil
	d.aggregatorPtr.Store(nil)
	d.aggSig = aggregatorSig{}
	d.aggReconMu.Unlock()
	if cancel != nil {
		cancel()
	}

	done := make(chan struct{})
	go func() {
		d.aggWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(aggregatorFlushJoinTimeout):
		slog.Warn("shutdown: timed out waiting for session-aggregation final "+
			"flush; proceeding to teardown (partial report dropped)",
			"timeout", aggregatorFlushJoinTimeout)
	}
}

// sethostname and hostnamePath are the kernel/disk seams of applyHostname,
// injectable so a unit test can exercise the post-rename management-TLS
// diagnostic (#6827) without CAP_SYS_ADMIN and without rewriting the test host's
// /etc/hostname.
var (
	sethostname  = syscall.Sethostname
	hostnamePath = "/etc/hostname"
	// osHostname reads the CURRENT kernel host name. The stale-cert diagnostic
	// reads it at delivery rather than storing a name at rename time (#6827).
	osHostname = os.Hostname
)

// applyHostname sets the system hostname from system { host-name } config.
func (d *Daemon) applyHostname(cfg *config.Config) {
	if cfg.System.HostName == "" {
		return
	}

	// Read through the seam, not os.Hostname directly. This early return is
	// LOAD-BEARING since #6827: the fenced rename below is reachable
	// only past it, so without it every commit carrying an unchanged
	// `system host-name` re-fires the debt and its delivery — and a box with a
	// genuinely stale durable cert would emit the "does not cover the current
	// host-name" WARN on EVERY commit. That is the diagnostic-muting failure
	// mode hostNameLikelyAccessIdentity's own doc block exists to avoid.
	//
	// It also has to use osHostname so a test can present a kernel name that
	// differs from the configured one. Reading os.Hostname here while the rest
	// of the function reads the seam made the guard untestable and let a
	// fixture describe a kernel state production cannot reach (#6827 r3).
	current, _ := osHostname()
	if current == cfg.System.HostName {
		return
	}

	// The rename and the staleness ledger move together, under ONE hold of
	// staleCertMu (#6827 round 7). Calling sethostname here and recording the
	// generation afterwards left a window in which the kernel had already been
	// renamed and nothing had recorded it, so a delivery running concurrently
	// re-validated against an unmoved generation and emitted a diagnosis naming
	// the host name the box had just left — the residual rounds 5 and 6 declared
	// unclosable. It is closable: make the generation exist before the window can
	// open. See renameHostNotingStaleMgmtCert.
	if err := d.renameHostNotingStaleMgmtCert(cfg.System.HostName); err != nil {
		slog.Warn("failed to set hostname", "err", err)
		return
	}

	// Persist to /etc/hostname (DurableState: node identity must survive
	// a power cut so the box keeps its configured name across reboot).
	if err := fsatomic.WriteFileDurable(hostnamePath, []byte(cfg.System.HostName+"\n"), 0644); err != nil {
		slog.Warn("failed to write /etc/hostname", "err", err)
	}
	slog.Info("hostname set", "hostname", cfg.System.HostName)

	// The kernel host name is one of the two identities baked into the DURABLE
	// management TLS cert (#1916 D6), and the cert is never re-minted, so the
	// rename above may have just made it stale. Deliver the diagnosis HERE,
	// inline with the successful rename, rather than anywhere earlier in the
	// apply: the management reconcile that could reload a cert runs EARLY in
	// applyConfigLocked (before the dataplane apply, so a credential revocation
	// survives an aborting commit) and would therefore see the OLD name. This
	// call site is both the only one a plain host-name commit reaches and the
	// only one where the new name is already the truth (#6827).
	//
	// It runs OUTSIDE the fence's hold because the delivery takes staleCertMu
	// itself; recording and attempting stay one path because this is the sole
	// caller of renameHostNotingStaleMgmtCert and it attempts unconditionally.
	d.deliverStaleMgmtCertDiagnosis()
}

// isProcessDisabled checks if a Junos process name is in the disabled list.
func isProcessDisabled(cfg *config.Config, name string) bool {
	for _, p := range cfg.System.DisabledProcesses {
		if p == name {
			return true
		}
	}
	return false
}

// DNS reconciliation moved to daemon_dns.go (#1715): xpf owns
// /etc/resolv.conf as a managed plain file via a single applySem-locked
// reconcileDNS. The former applySystemDNS (resolved drop-in + restart),
// restartResolved, and applyDNSService (disable resolved) were removed —
// their write-then-disable apply order was the dangling-symlink race.
// RenderResolvedDropin remains in pkg/daemon/system for any future
// resolved-owner mode but is no longer wired into the apply path.

// The two xpf-managed chrony files. Vars rather than consts so a test can
// point them at a temp dir and exercise the write/reload/retry-debt paths
// without a real /etc/chrony — the same seam convention sshdConfPath and
// sshKnownHostsPath already use in this file.
var (
	chronySourcesPath   = "/etc/chrony/sources.d/xpf.sources"
	chronyThresholdPath = "/etc/chrony/conf.d/xpf-threshold.conf"
)

func renderChronySources(servers []string) string {
	var b strings.Builder
	for _, server := range servers {
		// #4902 render belt: a leniently-loaded / peer-synced value that is not
		// a bare IP or a safe DNS hostname (e.g. an embedded space carrying a
		// second chrony directive token, or a malformed value) is skipped so it
		// cannot inject an extra source-line token or fail the chrony reload. The
		// strict commit gate (config.ValidateNTPServer) rejects it at commit.
		if err := config.ValidateNTPServer(server, nil); err != nil {
			slog.Warn("skipping invalid NTP server", "server", server, "err", err)
			continue
		}
		// Use "pool" for hostnames and "server" for literal IPs.
		directive := "pool"
		if net.ParseIP(server) != nil {
			directive = "server"
		}
		fmt.Fprintf(&b, "%s %s iburst\n", directive, server)
	}
	return b.String()
}

func renderChronyThreshold(threshold int, action string) string {
	if threshold <= 0 || action == "" {
		return ""
	}

	// Only "accept" and "reject" are valid actions. Log and ignore anything else.
	if action != "accept" && action != "reject" {
		slog.Warn("unsupported NTP threshold action, ignoring", "action", action)
		return ""
	}

	// Junos NTP threshold is configured in seconds; chrony directives use
	// seconds as well. "accept" logs offsets beyond the threshold while
	// allowing correction, and "reject" additionally refuses large changes
	// after the initial update.
	var b strings.Builder
	fmt.Fprintf(&b, "logchange %d\n", threshold)
	if action == "reject" {
		fmt.Fprintf(&b, "maxchange %d 1 -1\n", threshold)
	}
	return b.String()
}

func reconcileManagedFile(path, content string) (bool, error) {
	current, err := os.ReadFile(path)
	if err == nil && string(current) == content {
		return false, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("read %s: %w", path, err)
	}

	if content == "" {
		removeErr := os.Remove(path)
		if removeErr != nil && !os.IsNotExist(removeErr) {
			return false, fmt.Errorf("remove %s: %w", path, removeErr)
		}
		return removeErr == nil, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, fmt.Errorf("create dir for %s: %w", path, err)
	}
	// AtomicGeneratedConfig: regenerated from active config every apply; a
	// torn file is unacceptable but a power-cut loss self-heals next apply.
	if err := fsatomic.WriteFileAtomic(path, []byte(content), 0644); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}

// chronyRunCmd runs one chrony runtime-reload shell-out. A package var so the
// per-leg outcome reloadChronyRuntime reports (#6800) can be exercised
// hermetically — the leg outcomes are what the retained reload debt is built
// from, and driving them through a real chronyc/systemctl would make the cells
// depend on whether the dev host happens to run chrony.
//
// WaitDelay is the #1794 post-SIGKILL pipe-drain cap, preserved verbatim from
// the two call sites this replaced.
// chronySourcesReloadTimeout bounds the `chronyc reload sources` leg on its own,
// inside reloadChronyRuntime's 15s aggregate. See the call site for why.
var chronySourcesReloadTimeout = 5 * time.Second

var chronyRunCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}

// chronyReloadOutcome reports which REQUESTED chrony reload legs did not
// complete (#6800). A leg that was not requested is never reported as failed,
// so the caller can assign the outcome straight onto the retained debt.
type chronyReloadOutcome struct {
	sourcesFailed   bool
	thresholdFailed bool
}

// reloadChronyRuntime drives the chrony runtime reload for the legs whose
// managed file changed, and REPORTS which of those legs failed.
//
// #6800: it used to return nothing. The two managed files had already been
// written by the time it ran, so a failed reload left the on-disk state
// converged and the running chrony stale, and the next apply's `changed` flags
// (computed against the converged files) were false — the debt was erased and
// the reload was never retried. The outcome returned here is what the caller
// latches so the retry owner can replay it.
func reloadChronyRuntime(sourcesChanged, thresholdChanged bool) chronyReloadOutcome {
	var out chronyReloadOutcome
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if sourcesChanged {
		// The sources leg gets its OWN bounded context. Sharing the aggregate
		// deadline meant a single hung `chronyc` could consume all 15s, leaving
		// every threshold fallback below to run against an already-expired
		// context and fail instantly — 15 seconds of apply latency buying no
		// convergence on either leg, and a threshold reload that was never
		// really attempted. Bounding it separately keeps the aggregate as the
		// ceiling while guaranteeing the fallbacks a share.
		srcCtx, srcCancel := context.WithTimeout(ctx, chronySourcesReloadTimeout)
		defer srcCancel()
		if cmdOut, err := chronyRunCmd(srcCtx, "chronyc", "reload", "sources"); err != nil {
			slog.Warn("failed to reload chrony sources; will retry", "err", err, "output", string(cmdOut))
			out.sourcesFailed = true
		}
	}

	if !thresholdChanged {
		return out
	}

	commands := [][]string{
		{"systemctl", "reload", "chrony"},
		{"systemctl", "reload", "chronyd"},
		{"systemctl", "restart", "chrony"},
		{"systemctl", "restart", "chronyd"},
	}
	for _, cmd := range commands {
		if cmdOut, err := chronyRunCmd(ctx, cmd[0], cmd[1:]...); err == nil {
			return out
		} else {
			slog.Debug("chrony config reload attempt failed", "cmd", strings.Join(cmd, " "), "err", err, "output", string(cmdOut))
		}
	}
	slog.Warn("failed to reload chrony threshold config; will retry")
	out.thresholdFailed = true
	return out
}

// applySystemNTP configures chrony from system { ntp } config.
// Writes per-server source lines to /etc/chrony/sources.d/xpf.sources and
// optional threshold directives to /etc/chrony/conf.d/xpf-threshold.conf.
func (d *Daemon) applySystemNTP(cfg *config.Config) {
	// #6800: fold in any reload a previous apply still owes. The managed files
	// are already converged, so this apply's own change flags cannot re-derive
	// that debt — the ONLY record of it is what the failing reload latched.
	sourcesOwed, thresholdOwed := d.chronyReloadOwed()

	if isProcessDisabled(cfg, "ntp") {
		sourcesChanged, err := reconcileManagedFile(chronySourcesPath, "")
		if err != nil {
			slog.Warn("failed to remove chrony sources", "err", err)
		}
		thresholdChanged, err := reconcileManagedFile(chronyThresholdPath, "")
		if err != nil {
			slog.Warn("failed to remove chrony threshold config", "err", err)
		}
		sourcesChanged = sourcesChanged || sourcesOwed
		thresholdChanged = thresholdChanged || thresholdOwed
		if sourcesChanged || thresholdChanged {
			d.noteChronyReloadResult(chronyReloadFn(sourcesChanged, thresholdChanged))
			slog.Info("NTP disabled; chrony managed configuration removed")
		}
		return
	}

	sourcesChanged, err := reconcileManagedFile(chronySourcesPath, renderChronySources(cfg.System.NTPServers))
	if err != nil {
		slog.Warn("failed to reconcile chrony sources", "err", err)
		return
	}
	thresholdChanged, err := reconcileManagedFile(chronyThresholdPath, renderChronyThreshold(cfg.System.NTPThreshold, cfg.System.NTPThresholdAction))
	if err != nil {
		slog.Warn("failed to reconcile chrony threshold config", "err", err)
		return
	}
	sourcesChanged = sourcesChanged || sourcesOwed
	thresholdChanged = thresholdChanged || thresholdOwed
	if !sourcesChanged && !thresholdChanged {
		return
	}

	d.noteChronyReloadResult(chronyReloadFn(sourcesChanged, thresholdChanged))
	slog.Info("NTP config applied via chrony",
		"servers", cfg.System.NTPServers,
		"threshold", cfg.System.NTPThreshold,
		"action", cfg.System.NTPThresholdAction)
}

// applyKernelTuning sets kernel sysctl parameters from config.
// Handles system { no-redirects } and system { internet-options }.
func (d *Daemon) applyKernelTuning(cfg *config.Config) {
	// Disable ICMP redirects (send + accept) on all interfaces
	// system { no-redirects; }
	if cfg.System.NoRedirects {
		sysctls := []string{
			"/proc/sys/net/ipv4/conf/all/send_redirects",
			"/proc/sys/net/ipv4/conf/all/accept_redirects",
			"/proc/sys/net/ipv6/conf/all/accept_redirects",
		}
		for _, path := range sysctls {
			current, _ := os.ReadFile(path)
			if strings.TrimSpace(string(current)) != "0" {
				if err := os.WriteFile(path, []byte("0\n"), 0644); err != nil {
					slog.Warn("failed to set sysctl", "path", path, "err", err)
				}
			}
		}
	}

	// system { internet-options { no-ipv6-reject-zero-hop-limit; } }
	// Normally Linux drops IPv6 packets with hop-limit=0 and sends ICMPv6
	// time exceeded. This sysctl raises the ratelimit to effectively
	// accept them without generating errors (Junos compatibility).
	if cfg.System.InternetOptions != nil && cfg.System.InternetOptions.NoIPv6RejectZeroHopLimit {
		path := "/proc/sys/net/ipv6/icmp/ratelimit"
		current, _ := os.ReadFile(path)
		if strings.TrimSpace(string(current)) != "0" {
			if err := os.WriteFile(path, []byte("0\n"), 0644); err != nil {
				slog.Warn("failed to set sysctl", "path", path, "err", err)
			}
		}
	}

	// Kernel TRANSIT forwarding, gated on the dataplane being armed (#5275).
	//
	// This is the load-bearing half of the gate: the tail runs at EVERY
	// apply, so an unconditional "1" here re-opened policy-free kernel
	// routing on the next commit even after bring-up had failed closed —
	// which is how a node whose AF_XDP shim never attached stayed an open
	// router. Writing the armed state (rather than skipping the write when
	// unarmed) is deliberate: it also RE-ASSERTS the closure against
	// anything else that raised the knob since the last apply.
	writeTransitForwardSysctls(d.DataplaneArmed())
}

// sshKnownHostsPath is the OpenSSH global known-hosts file xpfd owns and fully
// rewrites from security { ssh-known-hosts }. Overridable in tests so the
// write/remove side effects can be exercised against a temp dir.
var sshKnownHostsPath = "/etc/ssh/ssh_known_hosts"

// sshKnownHostsHeader marks the file as xpf-owned. Both the write path and the
// empty-desired-state removal path key off this exact string: the daemon
// rewrites the file only when it renders content, and removes it only when the
// on-disk file begins with this header — never a hand-maintained/foreign
// ssh_known_hosts.
const sshKnownHostsHeader = "# Managed by xpfd — do not edit\n"

// applySSHKnownHosts writes /etc/ssh/ssh_known_hosts from
// security { ssh-known-hosts { host ... } } config. When the desired trust is
// cleared (no configured hosts) the xpf-owned file is REMOVED, so a revoked or
// compromised host key can never outlive the config that trusted it (#5112):
// applied durable trust must not outlive desired trust. The removal is
// ownership-guarded — a file lacking the managed header is left untouched.
func (d *Daemon) applySSHKnownHosts(cfg *config.Config) {
	path := sshKnownHostsPath
	if len(cfg.Security.SSHKnownHosts) == 0 {
		removeManagedSSHKnownHosts(path)
		return
	}

	var buf strings.Builder
	buf.WriteString(sshKnownHostsHeader)
	// Sort hosts for deterministic output
	var hosts []string
	for h := range cfg.Security.SSHKnownHosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		for _, key := range cfg.Security.SSHKnownHosts[host] {
			// Map Junos key type names to OpenSSH types
			sshType := key.Type
			switch sshType {
			case "ssh-rsa-key":
				sshType = "ssh-rsa"
			case "ecdsa-sha2-nistp256-key":
				sshType = "ecdsa-sha2-nistp256"
			case "ssh-ed25519-key":
				sshType = "ssh-ed25519"
			case "ecdsa-sha2-nistp384-key":
				sshType = "ecdsa-sha2-nistp384"
			case "ecdsa-sha2-nistp521-key":
				sshType = "ecdsa-sha2-nistp521"
			}
			fmt.Fprintf(&buf, "%s %s %s\n", host, sshType, key.Key)
		}
	}

	content := buf.String()
	current, _ := os.ReadFile(path)
	if string(current) == content {
		return
	}

	// AtomicGeneratedConfig (D2b): regenerated from declarative config and
	// governs only outbound host-key verification — a torn/lost file
	// re-renders next apply; no power-loss durability needed.
	if err := fsatomic.WriteFileAtomic(path, []byte(content), 0644); err != nil {
		slog.Warn("failed to write ssh known hosts", "err", err)
		return
	}
	slog.Info("SSH known hosts written", "hosts", len(cfg.Security.SSHKnownHosts))
}

// removeManagedSSHKnownHosts removes the xpf-owned ssh_known_hosts file when
// the desired trust is empty. It deletes the file ONLY when the on-disk
// content begins with the managed header, so a hand-maintained or otherwise
// foreign ssh_known_hosts is never touched. An absent file is a no-op.
//
// Unlike the write path (fsatomic.WriteFileAtomic — no fsync, because a
// lost-on-power-cut rewrite simply re-renders the SAME trust next apply), the
// removal is the DANGEROUS direction: a lost unlink would resurrect a revoked,
// now-untrusted host key on reboot. So the parent directory is fsynced after
// the unlink to make the removal durable across power loss.
func removeManagedSSHKnownHosts(path string) {
	current, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("failed to read ssh known hosts for removal", "path", path, "err", err)
		}
		return
	}
	if !strings.HasPrefix(string(current), sshKnownHostsHeader) {
		// Foreign / hand-maintained file — not ours to delete.
		return
	}
	if err := os.Remove(path); err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("failed to remove ssh known hosts", "path", path, "err", err)
		}
		return
	}
	if err := fsatomic.SyncDir(filepath.Dir(path)); err != nil {
		slog.Warn("failed to fsync dir after ssh known hosts removal", "path", path, "err", err)
	}
	slog.Info("SSH known hosts cleared; managed file removed", "path", path)
}

// zoneinfoRoot is the directory tree a `system time-zone` value may reference.
// The /etc/localtime symlink target MUST resolve to a path within this root.
const zoneinfoRoot = "/usr/share/zoneinfo"

// zoneinfoTarget builds the /etc/localtime symlink target for the given
// time-zone value and reports whether it stays within zoneinfoRoot. It is the
// #5011 render belt: even if a traversal value ("../../etc/shadow") slips past
// the commit-time config.ValidateTimeZone gate on the tolerant load /
// peer-sync path (#1960), the daemon refuses to point /etc/localtime outside
// the zoneinfo tree. filepath.Join cleans the joined path (collapsing any ".."
// segments), so the containment test runs on the resolved target rather than
// the raw string; for a legitimate zone (America/Los_Angeles, UTC, Etc/GMT+5)
// the result is byte-identical to the old "/usr/share/zoneinfo/" + tz concat,
// so the symlink idempotence compare is unaffected.
func zoneinfoTarget(tz string) (string, bool) {
	// An empty or absolute value is never a legitimate zone. filepath.Join
	// would otherwise re-root an absolute value into the tree ("/etc/passwd"
	// -> "/usr/share/zoneinfo/etc/passwd"), silently reinterpreting it; refuse
	// it outright so the belt's rejection set matches ValidateTimeZone.
	if tz == "" || filepath.IsAbs(tz) {
		return "", false
	}
	target := filepath.Join(zoneinfoRoot, tz)
	rel, err := filepath.Rel(zoneinfoRoot, target)
	if err != nil {
		return "", false
	}
	// rel == "." means tz resolved to the root itself ("."), which is a
	// directory, not a zone file; a ".." or "../" prefix means it escaped.
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", false
	}
	return target, true
}

// applyTimezone sets the system timezone from system { time-zone } config.
func (d *Daemon) applyTimezone(cfg *config.Config) {
	if cfg.System.TimeZone == "" {
		return
	}

	// #1916 Step 2b r4 case-split. The /etc/localtime symlink and the
	// /etc/timezone file are two pieces of the same setting; a prior crash
	// between the symlink write and the file write could leave them
	// inconsistent. The old code returned early whenever the symlink alone
	// matched, so a stale /etc/timezone would never be repaired (AGY r2 #3).
	// The naive fix (require BOTH to match before skipping, else fall
	// through) re-ran os.Remove("/etc/localtime")+Symlink even when the
	// symlink was already correct — a crash after the Remove would break a
	// correct symlink (Codex r3). So split the cases explicitly: only touch
	// the symlink when it is wrong; always (re)write /etc/timezone when its
	// content differs, including when the symlink was already correct.
	current, _ := os.Readlink("/etc/localtime")
	// #5011 render belt: resolve the symlink target and refuse to create
	// /etc/localtime if it escapes the zoneinfo root. The commit-time
	// ValidateTimeZone gate rejects a `..`/absolute value, but #1960
	// downgrades that to a warning on the tolerant load / peer-sync path, so
	// this fail-closed check is the real boundary against a traversal target.
	target, ok := zoneinfoTarget(cfg.System.TimeZone)
	if !ok {
		slog.Warn("refusing time-zone: symlink target escapes zoneinfo root",
			"timezone", cfg.System.TimeZone)
		return
	}

	tzContent := cfg.System.TimeZone + "\n"
	tzCurrent, _ := os.ReadFile("/etc/timezone")
	tzMatches := string(tzCurrent) == tzContent

	// Case 1: both pieces already correct → nothing to do.
	if current == target && tzMatches {
		return
	}

	// Verify the zoneinfo file exists before mutating anything.
	if _, err := os.Stat(target); err != nil {
		slog.Warn("invalid timezone", "timezone", cfg.System.TimeZone, "err", err)
		return
	}

	// Case 2: only re-run the symlink mutation when localtime is wrong; do
	// NOT remove an already-correct symlink (that opens a crash window).
	if current != target {
		os.Remove("/etc/localtime")
		if err := os.Symlink(target, "/etc/localtime"); err != nil {
			slog.Warn("failed to set timezone", "err", err)
			return
		}
	}

	// Case 3: always write /etc/timezone (AtomicGeneratedConfig) whenever
	// its content differs — including the symlink-already-correct branch,
	// which is how a "timezone-only stale" state gets repaired without
	// touching the good symlink.
	if !tzMatches {
		if err := fsatomic.WriteFileAtomic("/etc/timezone", []byte(tzContent), 0644); err != nil {
			slog.Warn("failed to write /etc/timezone", "err", err)
			return
		}
	}
	slog.Info("timezone set", "timezone", cfg.System.TimeZone)
}

// applySystemSyslog configures system-level syslog forwarding from
// system { syslog { host ... } } config. This forwards daemon log
// messages (Go slog) to remote syslog servers.
// syslogHostMinSeverity computes the SyslogClient.MinSeverity threshold for
// one syslog host from its `<facility> <severity>` selectors. It returns 0
// (no filter / send-all) when no APPLICABLE entry names a severity, matching
// the SyslogClient zero value.
//
// stampedFacility is the numeric facility code this host's client will stamp
// into every record it emits (SyslogClient.Facility, chosen by the caller from
// the authored selector list). It is the key, and it is what makes the
// selection Junos-shaped rather than a blind fold.
//
// #5797 — WHICH SELECTORS APPLY. Junos evaluates `<facility> <severity>`
// pairs INDEPENDENTLY: `daemon info; authorization critical` forwards daemon
// records at info-or-higher and authorization records at critical-or-higher.
// This function previously folded every pair to the single most restrictive
// severity, so that config filtered the WHOLE destination at critical and
// silently dropped the daemon notice/info records the operator explicitly
// asked for. `daemon info; authorization none` was worse: `none` outranks
// everything, so ONE selector naming a facility this client never emits
// silenced the entire destination.
//
// A selector can only match a record whose facility it names. Every record
// this client sends carries stampedFacility, so a selector resolving to a
// DIFFERENT facility code matches nothing this client will ever send and must
// not constrain it. Only two kinds of selector apply:
//
//   - the `any` wildcard (FacilityIsWildcard), which matches every record;
//   - a selector whose facility resolves to stampedFacility.
//
// Resolution is by numeric CODE, not by authored name, because the code is
// what appears in the wire PRI. Unmapped Junos names all resolve to local0
// (ParseFacility's fallback, warned about at the call site), so a host that
// actually stamps local0 is correctly constrained by them — the selector and
// the emitted record genuinely share a facility on the wire.
//
// Junos more-specific-wins: when at least one exact-code selector applies, the
// `any` wildcard does NOT also constrain the threshold. Two selectors naming
// the SAME code are a genuine conflict on one facility and still fold to the
// most restrictive of the two.
//
// RESIDUAL (tracked separately, NOT fixed here): a client carries one facility,
// so a host naming two mappable facilities can still only honor one of them,
// and which one is stamped depends on selector order. Honoring both needs a
// source facility on the event envelope and per-facility routing.
//
// ParseSeverity maps ALL ten Junos severities (#5314): emergency
// (SeverityEmergency), alert/critical/error/warning/notice/info/debug (raw
// RFC levels), plus any (0 = send-all) and none (SeverityNone = send-nothing).
// The prior inline guard tested `if sev > 0`, which silently dropped
// emergency/critical/alert/notice/debug/none (ParseSeverity returned 0 for
// them), so `host H <facility> critical` left MinSeverity at the 0 send-all
// sentinel and over-forwarded info/warning/error records the operator never
// authorized.
func syslogHostMinSeverity(facilities []config.SyslogFacility, stampedFacility int) int {
	exact := 0 // fold of selectors naming stampedFacility
	exactSet := false
	wild := 0 // fold of `any` selectors
	wildSet := false

	for _, f := range facilities {
		if f.Severity == "" {
			continue
		}
		sev := logging.ParseSeverity(f.Severity)
		switch {
		case logging.FacilityIsWildcard(f.Facility):
			if !wildSet {
				wild, wildSet = sev, true
			} else {
				wild = logging.MoreRestrictiveMinSeverity(wild, sev)
			}
		case logging.ParseFacility(f.Facility) == stampedFacility:
			if !exactSet {
				exact, exactSet = sev, true
			} else {
				exact = logging.MoreRestrictiveMinSeverity(exact, sev)
			}
		}
		// Any other selector names a facility this client never emits. It
		// matches nothing here, so it contributes nothing — that is the whole
		// #5797 correction.
	}

	// Junos more-specific-wins: an exact selector displaces the wildcard.
	if exactSet {
		return exact
	}
	if wildSet {
		return wild
	}
	return 0 // no applicable selector named a severity: send-all
}

func (d *Daemon) applySystemSyslog(cfg *config.Config) {
	if d.slogHandler == nil {
		return
	}

	if cfg.System.Syslog == nil || len(cfg.System.Syslog.Hosts) == 0 {
		d.slogHandler.SetClients(nil)
		return
	}

	var clients []*logging.SyslogClient
	for _, host := range cfg.System.Syslog.Hosts {
		// #4303 S-1: honor `host <h> port <n>` and `source-address <ip>`.
		// Both were previously misparsed into bogus facility entries and
		// never reached the client; the port stayed pinned at 514 and the
		// source bind was ignored.
		port := 514
		if host.Port > 0 {
			port = host.Port
		}
		// #6829: classify the facility BEFORE constructing the client, because
		// construction DIALS. NewSyslogClientWithSource resolves and dials
		// (logging/syslog.go), and on UDP a dial failure returns a nil client,
		// so the `continue` below used to skip the classification entirely — an
		// operator whose collector hostname does not resolve was never told
		// their facility name is also unmappable, which is the one diagnosis
		// that does not depend on the network being up. Classification reads
		// only the config, so it belongs on this side of the dial. It also makes
		// the warning observable in a restricted runner where socket creation is
		// denied, instead of the test dying at construction before reaching it.
		facility := logging.FacilityDaemon
		if len(host.Facilities) > 0 {
			// #5797: an UNMAPPED facility name silently resolved to local0 here,
			// so records left under a facility the operator never authored and
			// the collector's facility-based routing misfiled them with no
			// signal anywhere.
			//
			// There is NO commit gate on this name. `<facility> <severity>` is a
			// schema WILDCARD (syslogFacilitySeverityLeaf): the validator sits on
			// the severity VALUE, and the facility KEY has none — so an ordinary
			// `set system syslog host 10.0.0.1 authorization info` commits clean
			// and arrives here. That is not an exotic tolerant-load case: Junos
			// spells this vocabulary `authorization` / `kernel` /
			// `interactive-commands`, and ParseFacility knows only the
			// BSD/rsyslog spellings, so a correct-looking vSRX config is the
			// COMMON way to hit it.
			//
			// Forwarding is deliberately NOT withheld: which facility a
			// misconfigured host lands under is an availability-affecting
			// contract question, and the selector redesign owns it. The warning
			// is the whole fix — TestApplySystemSyslogWarnsOnUnmappedFacility_5797
			// pins that it fires.
			raw := host.Facilities[0].Facility
			f, known := logging.ParseFacilityChecked(raw)
			// #6829 A3: `any` is the canonical Junos wildcard and names no
			// facility on purpose — warning about it is a false alarm on a
			// correct config.
			if !known && !logging.FacilityIsWildcard(raw) {
				// #6830: say WHICH facility is wrong and what the right answer
				// is, not just that a substitution happened. Junos publishes
				// the mapping, so for a real Junos facility name the warning
				// can name the target — which is the difference between an
				// operator knowing something is off and knowing what to do.
				// A name in neither vocabulary is a typo and is reported as
				// one; conflating the two sent an operator looking for a
				// mapping bug when they had a spelling mistake, and vice
				// versa.
				// #6830: the MISFILED arm is gone because it can no longer be
				// reached. It described a name that IS in the documented Junos
				// vocabulary but which this box emitted under a different code
				// — and ParseFacility now consults that table first, so the
				// two agree by construction. Keeping a warning whose input
				// cannot occur would be dead code that no test can exercise
				// without a seam invented for it.
				//
				// The property it protected did not go away, it moved: pkg/logging's
				// TestNothingInTheTableIsMisfiled6830 asserts, over the whole
				// table, that the emit path and the documented mapping agree —
				// so a row added without wiring, or a wiring regression, reds
				// there rather than warning here.
				//
				// What reaches this branch now is a name in NEITHER vocabulary:
				// a typo, where local0 is a substitution for something that
				// means nothing.
				slog.Warn("system syslog: unrecognized facility name; local0 selected — "+
					"this name is not in the Junos `[edit system syslog]` vocabulary, so "+
					"it is most likely a typo. If this host's client is installed, its "+
					"records will carry a facility the configuration does not name (#5797)",
					"host", host.Address, "facility", raw, "using", "local0")
			}
			facility = f

			// #5797: a selector naming a facility OTHER than the one this
			// client stamps can never match a record it sends, so it no longer
			// contributes to the threshold (syslogHostMinSeverity). That is the
			// correct semantics, and it is also a silent no-op the operator has
			// no way to see — they asked for `authorization critical` and get
			// neither the records nor a complaint. Say so, once per apply.
			//
			// This is not the unmapped-name warning above: the name may be
			// perfectly well-formed (`kern`, `auth`) and still be inapplicable,
			// because a client carries ONE facility. Honoring several needs a
			// source facility on the event envelope, which is the successor
			// issue's architecture.
			for _, sel := range host.Facilities {
				if logging.FacilityIsWildcard(sel.Facility) ||
					logging.ParseFacility(sel.Facility) == facility {
					continue
				}
				slog.Warn("system syslog: selector names a facility this host's client does not "+
					"emit, so it selects nothing — every record to this host carries the "+
					"stamped facility (#5797)",
					"host", host.Address, "selector", sel.Facility,
					"severity", sel.Severity, "stamped", facility)
			}
		}

		c, err := logging.NewSyslogClientWithSource(host.Address, port, host.SourceAddress)
		if err != nil {
			slog.Warn("failed to create system syslog client",
				"host", host.Address, "err", err)
			continue
		}

		c.Facility = facility
		if len(host.Facilities) > 0 {
			// #5797: keyed on the facility this client actually stamps, so a
			// selector naming a DIFFERENT facility cannot restrict (or, with
			// `none`, silence) records it can never match.
			c.MinSeverity = syslogHostMinSeverity(host.Facilities, facility)
		}

		clients = append(clients, c)
		slog.Info("system syslog forwarding configured",
			"host", host.Address, "facility", c.Facility)
	}

	d.slogHandler.SetClients(clients)
}

// rsyslogConfDir is the directory holding the xpf-managed rsyslog drop-ins. A
// var rather than a literal so a test can reconcile against a temp dir instead
// of the host's real /etc/rsyslog.d.
var rsyslogConfDir = "/etc/rsyslog.d"

// applySyslogFiles writes rsyslog drop-in configs for system { syslog { file ... } }
// destinations. Each file entry generates a rule that directs matching
// facility/severity messages to /var/log/<name>.
func (d *Daemon) applySyslogFiles(cfg *config.Config) {
	confDir := rsyslogConfDir
	prefix := "10-xpf-"

	desired := syslogDropinContents(cfg, prefix)

	// Reconcile the on-disk managed drop-ins against `desired`. A removal OR a
	// (re)write flips `changed`, which gates the single restart below.
	changed := reconcileSyslogDropins(confDir, prefix, desired)

	// #6800: the `changed` gate alone erased the debt of a FAILED restart. The
	// reconcile above had already converged the drop-ins, so once a restart
	// failed, every later apply compared desired against the converged files,
	// saw no change, skipped the restart, and rsyslog kept serving the previous
	// ruleset — records still flowing to a destination the operator removed —
	// until an unrelated syslog edit or a reboot. The retained debt is the only
	// record of that owed restart, so it joins the gate here (the prompt path)
	// and is re-driven by serviceReloadDebtReassertLoop (the always-on path).
	if changed || d.rsyslogRestartOwed() {
		out, err := rsyslogRestartFn()
		d.noteRsyslogRestartResult(err)
		if err != nil {
			slog.Error("failed to restart rsyslog; the managed drop-ins are on disk "+
				"but rsyslog has not re-read them — will retry",
				"err", err, "output", strings.TrimSpace(string(out)))
		} else {
			slog.Info("rsyslog file configs applied", "files", len(desired))
		}
	}
}

// syslogDropinContents renders the xpf-managed rsyslog drop-ins for the
// `system syslog file` and `system syslog user` destinations, keyed by drop-in
// filename. It is the RENDER path: every value that reaches an rsyslog
// selector line is validated here, and a destination that fails validation is
// OMITTED from the returned map — which makes the caller's reconcile REMOVE any
// drop-in a previous apply wrote for it, rather than merely declining to
// rewrite it.
//
// Split out of applySyslogFiles (#5797 review) so the belts below are testable
// at the site that actually consults them. Testing syslogSelectorFacilitySafe
// / syslogSelectorSeveritySafe in isolation proves the predicates, not that the
// render path calls them; that gap is exactly how a belt gets deleted with a
// green suite.
// syslog_selector_render_5797_test.go drives this function.
func syslogDropinContents(cfg *config.Config, prefix string) map[string]string {
	desired := make(map[string]string) // filename -> content
	if cfg.System.Syslog != nil {
		for _, f := range cfg.System.Syslog.Files {
			if f.Name == "" {
				continue
			}
			// #4902 render belt: the name is formatted into /var/log/<name> and
			// the drop-in filename 10-xpf-<name>.conf. Skip a leniently-loaded /
			// peer-synced name with a path separator / `..` / whitespace /
			// control char so it cannot escape /var/log or inject an rsyslog
			// directive. The strict commit gate (config.ValidateSyslogFileName)
			// rejects it at commit.
			if err := config.ValidateSyslogFileName(f.Name, nil); err != nil {
				slog.Warn("skipping invalid syslog file destination", "name", f.Name, "err", err)
				continue
			}
			// #5797 render belt: the facility and severity tokens are
			// interpolated VERBATIM into the rsyslog selector below — the very
			// line #4902 already belts the file NAME for. #4902 stopped one
			// field short: a selector metacharacter or control byte in either
			// token escapes the intended selector and injects rsyslog
			// configuration. Shape-check both, and skip the destination rather
			// than write a drop-in built from an unsafe token.
			//
			// The two tokens have DIFFERENT reachability, and the facility is
			// the worse one. The severity is a typed enum leaf at commit
			// (syslogFacilitySeverityLeaf -> ValidateEnum(junosSyslogSeverities)),
			// so an unsafe severity only arrives on the tolerant load /
			// peer-sync path, like #4902's fields. The FACILITY is the schema's
			// wildcard KEY and carries NO key validator, so
			// `set system syslog file audit "daemon;*.* /tmp/pwn" info` passes
			// SchemaValidate, compiles, and lands here verbatim from an ORDINARY
			// operator commit. This belt is the only thing between that string
			// and a written rsyslog directive.
			// TestSyslogRenderUnsafeFacilityIsLoadReachable_5797 pins that
			// chain end to end.
			//
			// This is deliberately a SHAPE check, not a facility-name allowlist.
			// Closing the name set requires first reconciling the Junos facility
			// vocabulary (`authorization`, `kernel`, `interactive-commands`, ...)
			// against the BSD/rsyslog names the runtime maps (`auth`, `kern`,
			// ...) — an operator-visible mapping decision tracked on #5797, not
			// something to guess at here. The shape check is correct regardless
			// of how that lands.
			//
			// The shape is POSITION-AWARE: rsyslog's facility position takes a
			// comma list and a bare `*`, its priority position takes `*` and the
			// `=`/`!`/`!=` modifiers, and neither position's native syntax is
			// the other's. One allowlist applied to both would have to be the
			// intersection, which drops working destinations.
			if !syslogSelectorFacilitySafe(f.Facility) || !syslogSelectorSeveritySafe(f.Severity) {
				slog.Warn("skipping syslog file destination with unsafe selector token (#5797)",
					"name", f.Name, "facility", f.Facility, "severity", f.Severity)
				continue
			}
			// Map Junos facility/severity to rsyslog selector
			facility := f.Facility
			if facility == "" || facility == "any" {
				facility = "*"
			}
			// Junos "change-log" maps to local6; rsyslog doesn't know the name
			if facility == "change-log" {
				facility = "local6"
			}
			severity := f.Severity
			if severity == "" || severity == "any" {
				severity = "*"
			}
			// Junos severity names map directly to rsyslog (info, warning, error, etc.)
			selector := fmt.Sprintf("%s.%s", facility, severity)
			logPath := fmt.Sprintf("/var/log/%s", f.Name)

			content := fmt.Sprintf("# Managed by xpf — do not edit\n%s\t%s\n", selector, logPath)
			confFile := prefix + f.Name + ".conf"
			desired[confFile] = content
		}
		// Syslog user destinations: forward to logged-in users via rsyslog omusrmsg
		for _, u := range cfg.System.Syslog.Users {
			if u.User == "" {
				continue
			}
			// #4902 render belt: the user token is formatted into the drop-in
			// filename and the rsyslog `:omusrmsg:<user>` directive. Skip a
			// leniently-loaded / peer-synced value that is not '*' or a safe
			// account name. The strict commit gate (config.ValidateSyslogUser)
			// rejects it at commit.
			if err := config.ValidateSyslogUser(u.User, nil); err != nil {
				slog.Warn("skipping invalid syslog user destination", "user", u.User, "err", err)
				continue
			}
			// #5797 render belt: same rsyslog-selector interpolation as the file
			// destinations above, and the same asymmetry — the severity is
			// enum-gated at commit, the facility is an unvalidated wildcard KEY
			// and reaches here verbatim from an ordinary commit. Same
			// position-aware pair of predicates, deliberately kept identical to
			// the file site: a destination that renders as a file must render as
			// a user, and vice versa.
			if !syslogSelectorFacilitySafe(u.Facility) || !syslogSelectorSeveritySafe(u.Severity) {
				slog.Warn("skipping syslog user destination with unsafe selector token (#5797)",
					"user", u.User, "facility", u.Facility, "severity", u.Severity)
				continue
			}
			facility := u.Facility
			if facility == "" || facility == "any" {
				facility = "*"
			}
			if facility == "change-log" {
				facility = "local6"
			}
			severity := u.Severity
			if severity == "" || severity == "any" {
				severity = "*"
			}
			selector := fmt.Sprintf("%s.%s", facility, severity)
			target := u.User // "*" means all logged-in users
			content := fmt.Sprintf("# Managed by xpf — do not edit\n%s\t:omusrmsg:%s\n", selector, target)
			confFile := prefix + "user-" + target + ".conf"
			desired[confFile] = content
		}
	}
	return desired
}

// reconcileSyslogDropins removes stale xpf-managed rsyslog drop-ins (any file
// under confDir whose name starts with prefix that is not present in desired)
// and writes the desired drop-ins. It returns true when the on-disk managed
// set actually changed — a file was removed OR a file was (re)written — which
// the caller uses to gate the single `systemctl restart rsyslog`.
//
// #5111: a successful removal MUST count as a change, even when `desired` is
// empty. Removing the final managed destination leaves nothing to write, so
// the write loop cannot set `changed`; before this fix `changed` stayed false
// and the restart was skipped, leaving rsyslog with the deleted rule still
// loaded (logs kept flowing to a removed destination — an audit/confidentiality
// leak). A no-op remove of an already-absent file (os.IsNotExist) does NOT count
// so a steady-state reconcile does not spuriously restart rsyslog every apply.
// os.Remove errors are surfaced (slog.Warn) rather than discarded, and still
// mark a change so the restart re-reads config instead of silently stranding a
// stale rule with no restart.
func reconcileSyslogDropins(confDir, prefix string, desired map[string]string) bool {
	changed := false

	// Remove stale xpf-managed files.
	entries, _ := os.ReadDir(confDir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		if _, keep := desired[e.Name()]; keep {
			continue
		}
		path := filepath.Join(confDir, e.Name())
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				// Already gone — nothing was actually removed, so no restart
				// is owed for this entry.
				continue
			}
			// A partial/failed removal is still a config change we want
			// rsyslog to re-read; surface the error instead of discarding it.
			slog.Warn("failed to remove stale rsyslog config",
				"file", e.Name(), "err", err)
		}
		changed = true
	}

	// Write desired configs.
	for name, content := range desired {
		path := filepath.Join(confDir, name)
		current, _ := os.ReadFile(path)
		if string(current) != content {
			// AtomicGeneratedConfig: regenerated each apply.
			if err := fsatomic.WriteFileAtomic(path, []byte(content), 0644); err != nil {
				slog.Warn("failed to write rsyslog config", "file", name, "err", err)
				continue
			}
			changed = true
		}
	}

	return changed
}

// syslogSelectorAtomSafe reports whether a single selector ATOM — one facility
// name, or one severity name — is inert inside an rsyslog selector line
// (#5797).
//
// syslogDropinContents builds `<facility>.<severity>\t<target>` and writes it
// to a managed drop-in under /etc/rsyslog.d. #4902 already belts the file NAME
// and the user TOKEN on that same line, but left the two selector tokens
// unchecked — a `;` (rsyslog statement separator), a `.` (selector grammar), a
// space (selector/action separator) or a control byte in either one escapes the
// intended selector and injects rsyslog configuration.
//
// The severity reaches this only on the tolerant load / peer-sync path (it is
// an enum leaf at commit). The FACILITY reaches it from an ordinary commit: it
// is the schema's wildcard KEY and has no key validator, so
// `set system syslog file audit "daemon;*.* /tmp/pwn" info` commits clean.
//
// An atom is never empty: emptiness is a POSITION-level question (an unset
// facility folds to `*` at the render site, an empty member of a comma list is
// a malformed list), so the two position predicates below decide it and this
// one rejects it.
//
// What actually reaches these tokens, measured rather than assumed. A literal
// NEWLINE cannot: the lexer normalizes \n and \t inside a quoted value to a
// space, in both the hierarchical-quoted and the flat-set/peer-sync paths, so
// the classic "terminate the line and write a fresh directive" injection is
// not reachable through the config surface. But a newline is not required.
// Spaces and every rsyslog metacharacter survive VERBATIM — a quoted
// `"daemon;*.*"` arrives intact and a bare `*.*` arrives intact, on the
// FACILITY straight through SchemaValidate + CompileConfig, and on the
// severity via the tolerant load / peer-sync path. Because the emitted line is
// `<facility>.<severity>\t<target>` and rsyslog's grammar is
// `<selector><whitespace><action>`, a token containing a SPACE can push text
// into the ACTION position of a managed rsyslog line — e.g. a facility of
// `* @@collector.example:514` renders `* @@collector.example:514.info`
// ahead of the intended target. Whether rsyslog honours any specific such
// construction is NOT verified here (no rsyslog in the dev/CI environment), so
// this is deliberately not claimed as proven remote-forward exfiltration; it
// is more than a merely wrong selector, and the belt closes it either way by
// rejecting the space along with the metacharacters.
//
// Every real Junos facility and severity NAME — `daemon`, `authorization`,
// `change-log`, `interactive-commands`, `local0`..`local7`, `any`, `none`,
// `emergency`..`debug` — is ASCII letters, digits and hyphen, so this accepts
// the whole legitimate vocabulary (including the Junos names the runtime does
// not yet MAP) while rejecting anything that could alter the file's structure.
// It deliberately does NOT decide which facility NAMES are honoured; that is
// the deferred mapping question on #5797.
func syslogSelectorAtomSafe(atom string) bool {
	// #6844: SINGLE-SOURCED into pkg/config. The commit-time facility gate uses
	// the same predicate, so what the commit path ACCEPTS and what this belt
	// WRITES cannot diverge. Two copies would drift, and the drift has a name:
	// a config that commits cleanly and whose destination then silently
	// disappears at render. The rationale above now lives with the rule.
	return config.SyslogSelectorAtomSafe(atom)
}

// syslogSelectorFacilitySafe reports whether a facility token can be
// interpolated into the FACILITY position of an rsyslog selector without
// escaping it (#5797).
//
// The belt is position-aware because rsyslog's selector grammar is
// (rsyslog.conf(5), sysklogd format): the selector is
// `<facility>.<priority>`; `*` "stands for all facilities or all priorities,
// depending on where it is used (before or after the period)"; and "you can
// specify multiple facilities with the same priority pattern in one statement
// using the comma (`,`) operator". Both of those are NATIVE syntax in this
// position, and an earlier revision of this belt — a single byte-allowlist
// applied to both positions — rejected them.
//
// That was not a conservative choice, it was a silent regression. Both
// spellings pass SchemaValidate and compile verbatim (the facility is the
// schema's unvalidated wildcard KEY), and both rendered a working drop-in
// before the belt existed, so rejecting them made a strict-commit-clean,
// rsyslog-valid destination be warned-and-reconciled-AWAY on upgrade.
//
// Admitting them costs nothing, because neither can carry a payload:
//
//   - `*` is accepted only as the WHOLE token. `*` is one byte and the render
//     is `fmt.Sprintf("%s.%s", facility, severity)`, so it can only ever
//     produce `*.<severity>` — there is no room for an embedded `;`, space, or
//     second selector. It is not admitted as a list member (`*,auth`), which
//     is degenerate anyway: `*` already means every facility.
//   - a comma list is accepted only when EVERY member is a nonempty safe atom,
//     so `auth,authpriv` renders `auth,authpriv.info` while `auth,`, `,auth`
//     and `auth,,authpriv` are rejected. An empty member is malformed rsyslog,
//     and accepting it would let the length of the accepted set stop being a
//     function of the bytes in it.
//
// Everything the single allowlist rejected for structural reasons — `;`, `.`,
// `:`, whitespace, control bytes, arbitrary punctuation — is still rejected,
// in every position. `daemon;*.* /tmp/pwn` is still dropped; that is the
// injection this belt exists for.
//
// Empty is SAFE and expected: the call sites fold an empty facility to the `*`
// wildcard before building the selector, so an unset facility is ordinary
// configuration, not an omission to reject. `any` needs no special case — it
// is a safe atom, and the call sites fold it to `*` too.
//
// Note what this does NOT do, unchanged from the deferred #5797 mapping
// question: the render site's `change-log` -> `local6` remap and the
// `any` -> `*` fold are whole-token comparisons, so a LIST member spelled
// `change-log` or `any` is passed through verbatim and rsyslog will reject that
// selector. That is pre-existing behaviour (before any belt existed the whole
// facility rendered verbatim), and this belt deliberately does not decide
// facility NAMES.
func syslogSelectorFacilitySafe(tok string) bool {
	// #6844: SINGLE-SOURCED into pkg/config — see syslogSelectorAtomSafe above.
	return config.SyslogSelectorFacilitySafe(tok)
}

// syslogSelectorSeveritySafe reports whether a severity token can be
// interpolated into the PRIORITY position of an rsyslog selector without
// escaping it (#5797).
//
// The priority position has a different grammar from the facility position,
// which is why this is a separate predicate rather than the same one applied
// twice. Per rsyslog.conf(5): `*` stands for all priorities here too, and
// rsyslog extends BSD syslog with the modifiers `=` ("specify only this single
// priority and not any of the above"), `!` ("ignore all that priorities"), and
// the two combined — with the constraint that "the exclamation mark must occur
// before the equals sign". So `=info`, `!info` and `!=info` are native, and
// `=!info` is not; stripping only the three legal prefixes rejects the illegal
// ordering for free.
//
// A comma list is deliberately NOT accepted here. The comma operator is
// defined on the facility side only — rsyslog.conf(5) specifies multiple
// facilities "with the same priority pattern", and the priority itself is a
// single keyword. Multiple priorities are expressed by joining whole selectors
// with `;` (`kern.*;kern.!err`), and `;` is precisely the statement separator
// this belt exists to reject. So admitting a severity comma list would widen
// the accept set without recovering any working configuration: `daemon.info,err`
// was never a valid selector, on this branch or before the belt existed.
//
// Empty is SAFE for the same reason as the facility: the call sites fold it to
// `*`.
func syslogSelectorSeveritySafe(tok string) bool {
	if tok == "" {
		return true
	}
	// Order matters: `!=` must be stripped before `!`, or the `=` is left in
	// the atom and a legitimate `!=info` is rejected.
	rest := tok
	switch {
	case strings.HasPrefix(rest, "!="):
		rest = rest[2:]
	case strings.HasPrefix(rest, "!"), strings.HasPrefix(rest, "="):
		rest = rest[1:]
	}
	// A bare modifier with no priority after it (`!`, `=`, `!=`) leaves an
	// empty atom, which syslogSelectorAtomSafe rejects.
	if rest == "*" {
		return true
	}
	return syslogSelectorAtomSafe(rest)
}
