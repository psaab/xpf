package userspace

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
)

// helperEventSocketPath resolves the event-socket path for a helper config: the
// explicit `event-socket` when the operator set one, else the conventional name
// beside the control socket. The pre-stop preflight and the listener setup both
// resolve it through here, so they can never disagree about which path was
// validated (#5839).
func helperEventSocketPath(cfg config.UserspaceConfig) string {
	if cfg.EventSocket != "" {
		return cfg.EventSocket
	}
	return filepath.Join(filepath.Dir(cfg.ControlSocket), "userspace-dp-events.sock")
}

// preflightHelperPaths rejects a helper path set that bring-up would have to
// refuse anyway, while the RUNNING generation can still be spared (#5839).
//
// ensureProcessLocked stops generation N before it prepares generation N+1, so
// without a preflight every path fault is paid for with forwarding: the healthy
// helper is killed, socket preparation then fails, and the node is left with no
// dataplane at all. The two checks here are exactly the DETERMINISTIC faults —
// an aliased path, and a path that exists as something other than a Unix socket
// — neither of which stopping the helper can change. Everything conditional on
// the running helper is deliberately left to removeStaleUnixSocket after the
// stop; above all the liveness check, since the control socket is live PRECISELY
// UNTIL we stop the helper that owns it.
//
// It fails only on a certain fault. An Lstat error other than "does not exist"
// is inconclusive here and is left to the post-stop path rather than turned into
// a new bring-up failure on a code path that used to have none.
func preflightHelperPaths(cfg config.UserspaceConfig) error {
	evtPath := helperEventSocketPath(cfg)
	// The stale-socket primitive must never be pointed at the state file: a
	// REGULAR FILE is expected there, so aliasing it onto a socket path would
	// hand helper state to a socket unlink. Aliasing the two sockets onto each
	// other is equally unworkable — the daemon's event listener would occupy
	// the path the helper must bind.
	for _, pair := range []struct{ aName, a, bName, b string }{
		{"control-socket", cfg.ControlSocket, "event socket", evtPath},
		{"control-socket", cfg.ControlSocket, "state-file", cfg.StateFile},
		{"event socket", evtPath, "state-file", cfg.StateFile},
	} {
		if pair.a != "" && pair.a == pair.b {
			return fmt.Errorf("userspace dataplane %s and %s must name distinct paths (both are %s)",
				pair.aName, pair.bName, pair.a)
		}
	}
	for _, sock := range []struct{ kind, path string }{
		{socketKindControl, cfg.ControlSocket},
		{socketKindEventStream, evtPath},
	} {
		if sock.path == "" {
			continue
		}
		info, err := os.Lstat(sock.path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("userspace dataplane %s %s is a %s, not a Unix socket",
				sock.kind, sock.path, describeFileMode(info.Mode()))
		}
	}
	return nil
}

// stopForNewGenerationLocked preflights the incoming path set and tears the
// running helper down only once that preflight passes, so a config that cannot
// bring up a new generation leaves the previous one — and its forwarding —
// running (#5839).
// defaultPollMode is the `--poll-mode` value used when none is configured.
// SINGLE SOURCE: both the spawn path and configEqual read it through
// effectivePollMode, so the comparison cannot drift from the argv (#8899).
const defaultPollMode = "busy-poll"

func (m *Manager) stopForNewGenerationLocked(cfg config.UserspaceConfig) error {
	if err := preflightHelperPaths(cfg); err != nil {
		return fmt.Errorf("refusing to restart userspace dataplane helper, "+
			"previous generation left running: %w", err)
	}
	m.stopLocked()
	return nil
}

// clearStaleSteeringRows deletes every row in the pinned userspace_sessions map.
//
// #9770: the first-enable flush used to do this after the helper had already published
// live sessions, deleting their steering rows. At helper-spawn time no row can be live —
// the previous generation is reaped (crash: supervisor Wait; stop: done-wait; plus the
// live-listener refusal above the call site) and the new one does not exist yet (the call
// precedes cmd.Start) — so every row is previous-incarnation stale. TRUE ORDERING
// REQUIREMENT: before the first apply_snapshot reaches the helper; before-cmd.Start is the
// enforced stronger form. The same function serves the post-stop closer
// (drainAndClearSteeringRowsLocked), whose fence proof lives there.
//
// A nil map (test-only: production Load precedes every spawn) logs at debug and returns 0.
// Best-effort like the loop it replaces: the count is deletion ATTEMPTS, not verified
// deletions. Returns rows deleted.
func clearStaleSteeringRows(usMap *ebpf.Map) (deleted int) {
	if usMap == nil {
		slog.Debug("userspace: no steering map handle; nothing to clear")
		return 0
	}
	key := make([]byte, usMap.KeySize())
	nextKey := make([]byte, usMap.KeySize())
	for {
		if err := usMap.NextKey(key, nextKey); err != nil {
			break
		}
		copy(key, nextKey)
		_ = usMap.Delete(key)
		deleted++
	}
	return deleted
}

// drainAndClearSteeringRowsLocked reclaims steering rows orphaned by a proven full stop,
// but ONLY before this helper generation ever enabled (see below). Callers: every Go
// emitter of set_forwarding_state armed=false — SetForwardingArmed, PrepareLinkCycle's
// stop_workers, disarmBeforeUnsupportedPublishLocked, syncDesiredForwardingStateLocked
// (disarm arm only), disarmSnapshotProtocolFailureLocked — each immediately after its
// RPC succeeds (on any stop failure the caller skips this: the stop is uncertain and
// rows may be live). A future sixth emitter must call this too; see the census note.
//
// Why gated on never-enabled (#9770 PR review): post-enable, disarm-orphaned REDIRECT
// rows are load-bearing for recovery — the re-armed helper has no authority for them,
// so a lingering row forces the next packet into re-adjudication (policy runs, session
// reinstalls), while a deleted one misses to the kernel with no filter and no reinstall.
// Clearing post-enable would trade today's lingering-row recovery for permanent bypass
// on dead-session host-bound flows — the original defect in a new form. Pre-enable there
// is no recovery role (nothing ever forwarded in this generation) and the removed
// enable-time flush used to reclaim exactly these rows, so the closer preserves today's
// pre-enable behavior while fixing live-row deletion. Post-enable it is a no-op by
// design (parity: today's consumed gate covers post-enable disarms no better).
// Fence: m.mu is held (all callers); this takes m.sessionMu, draining every session
// send (all production sends serialize on it), and then pings the session socket — the
// helper serves that socket synchronously in accept order over a FIFO backlog, so the
// ping's ack proves every prior-sent request completed before the clear. Post-clear sends
// resolve defaulted maps and no-op their publishes (entries they insert are live authority
// the next bringup replays). Re-arm/rebind take m.mu and cannot publish concurrently.
// Lock order m.mu -> sessionMu is safe: every sessionMu holder releases it before taking
// m.mu. The disarm/stop RPC itself runs BEFORE sessionMu is taken, so session sync never
// stalls across worker joins; this hold is a ping RTT plus a map walk.
// Failure semantics: a drain (ping) failure or nil map skips the clear with a warning and
// returns nil — best-effort reclamation that never deletes on uncertainty and never fails
// the primary operation. Orphans from a failed stop linger until the next successful
// disarm/stop or spawn, which clears them under a re-established fence.
//
// Census note: the five call sites above are, as of this writing, every Go emitter of a
// full stop (set_forwarding_state armed=false, stop_workers). A new emitter that stops
// workers and clears authority must call this after its RPC succeeds, or pre-enable
// orphans from its path linger until the next spawn. There is no textual census test —
// the set_forwarding_state emitters are already enumerated (with lease gating) in the
// #6871 comment at syncDesiredForwardingStateLocked; keep the two lists in sync.
func (m *Manager) drainAndClearSteeringRowsLocked(reason string) {
	if m.initialCtrlCleanupDone {
		slog.Debug("userspace: helper generation already enabled; keeping disarm-orphaned rows for failback recovery",
			"reason", reason)
		return
	}
	usMap := m.bpfShim.Map(mapNameUserspaceSessions)
	if usMap == nil {
		slog.Debug("userspace: no steering map handle; nothing to clear", "reason", reason)
		return
	}
	if m.sessionSocketPath() != "" {
		m.sessionMu.Lock()
		defer m.sessionMu.Unlock()
		// #9629: this ping is served off-lock (the session allowlist serves
		// ping without ServerState), so the fence holds even mid-apply — no
		// 10s wedge stalling the session thread behind snapshot application.
		ping := ControlRequest{Type: "ping", SuppressStatus: true}
		if err := m.requestSessionSyncLocked(ping); err != nil {
			slog.Warn("userspace: session drain failed; keeping possibly-orphaned steering rows",
				"reason", reason, "err", err)
			return
		}
	}
	if deleted := clearStaleSteeringRows(usMap); deleted > 0 {
		slog.Info("userspace: reclaimed orphaned steering rows after full stop",
			"reason", reason, "deleted", deleted)
	}
}

const startupNAPIBootstrapDelay = 3 * time.Second

// scheduleStartupNAPIBootstrapLocked arms the delayed startup NAPI bootstrap
// for the helper generation that was just spawned. The callback captures both
// the process-generation fence and the helper identities while m.mu is held;
// after the delay it re-checks them under the same lock before submitting any
// probes. A callback from a stopped or crashed generation therefore becomes a
// no-op even when a replacement helper is already running (#10436).
func (m *Manager) scheduleStartupNAPIBootstrapLocked() {
	m.scheduleStartupNAPIBootstrapAfterLocked(startupNAPIBootstrapDelay)
}

// scheduleStartupNAPIBootstrapAfterLocked is the same generation-fenced
// callback with an injected delay for deterministic lifecycle tests.
func (m *Manager) scheduleStartupNAPIBootstrapAfterLocked(delay time.Duration) <-chan struct{} {
	procGen := m.procGen
	proc := m.proc
	procSup := m.procSup
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(delay)
		m.mu.Lock()
		if !m.startupNAPIBootstrapGenerationCurrentLocked(procGen, proc, procSup) {
			m.mu.Unlock()
			return
		}
		innerDone := m.bootstrapNAPIQueuesAsyncForGenerationLocked("startup", procGen, proc, procSup)
		m.mu.Unlock()
		<-innerDone
	}()
	return done
}

func (m *Manager) startupNAPIBootstrapGenerationCurrentLocked(
	procGen uint64,
	proc *exec.Cmd,
	procSup *helperGeneration,
) bool {
	return m.proc != nil &&
		m.procGen == procGen &&
		m.proc == proc &&
		m.procSup == procSup
}

// bootstrapNAPIQueuesAsyncForGenerationLocked is the generation-fenced
// startup variant of bootstrapNAPIQueuesAsyncLocked. The second callback
// acquires m.mu independently, so it must repeat the same identity check:
// generation G1 can stop after the delayed callback starts but before this
// inner callback runs, at which point G2 may already own m.proc (#10436).
func (m *Manager) bootstrapNAPIQueuesAsyncForGenerationLocked(
	reason string,
	procGen uint64,
	proc *exec.Cmd,
	procSup *helperGeneration,
) <-chan struct{} {
	done := make(chan struct{})
	now := time.Now()
	if !m.lastNAPIBootstrap.IsZero() && now.Sub(m.lastNAPIBootstrap) < 2*time.Second {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.startupNAPIBootstrapGenerationCurrentLocked(procGen, proc, procSup) {
			return
		}
		now := time.Now()
		if !m.lastNAPIBootstrap.IsZero() && now.Sub(m.lastNAPIBootstrap) < 2*time.Second {
			return
		}
		m.lastNAPIBootstrap = now
		if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
			return
		}
		slog.Info("userspace: bootstrapping NAPI queues", "reason", reason)
		m.bootstrapNAPIQueuesLocked()
	}()
	return done
}

func (m *Manager) ensureProcessLocked(cfg config.UserspaceConfig) error {
	tuneSocketBuffers()
	if m.proc != nil && m.proc.Process != nil && configEqual(m.cfg, cfg) {
		var status ProcessStatus
		if err := m.requestLocked(ControlRequest{Type: "ping"}, &status); err == nil {
			if status.PID != 0 || status.ConfigSnapshotProtocolVersion != 0 {
				m.setLastStatusLocked(status)
			}
			return nil
		}
		slog.Warn("userspace dataplane helper unhealthy, restarting")
		if err := m.stopForNewGenerationLocked(cfg); err != nil {
			return err
		}
	}
	if m.proc != nil {
		if err := m.stopForNewGenerationLocked(cfg); err != nil {
			return err
		}
	}
	m.clearLastStatusLocked()
	binary, err := findBinary(cfg.Binary)
	if err != nil {
		return err
	}
	// #9003: create-and-PROVE, not create-and-assume. os.MkdirAll returns nil
	// for a directory that already exists and never looks at its owner or mode,
	// so the previous `os.MkdirAll(dir, 0755)` adopted whatever was there —
	// including a directory an unprivileged local user created first, inside
	// which they can unlink the socket the root helper binds and substitute
	// their own. ensureTrustedRuntimeDir refuses a directory this daemon cannot
	// vouch for, BEFORE the helper is spawned, so the failure costs nothing
	// beyond the generation that was already stopped.
	if err := ensureTrustedRuntimeDir("control socket", filepath.Dir(cfg.ControlSocket)); err != nil {
		return err
	}
	if err := ensureTrustedRuntimeDir("state file", filepath.Dir(cfg.StateFile)); err != nil {
		return err
	}
	// The control socket is named by operator configuration and xpfd runs as
	// root, so the stale-socket unlink is guarded rather than fire-and-forget:
	// it refuses a path that is not a Unix socket, refuses one a live listener
	// still holds, and surfaces a removal failure instead of discarding it
	// (#5839). The helper has not been spawned yet, so failing here costs
	// nothing beyond the generation that was already stopped.
	if err := removeStaleUnixSocket(socketKindControl, cfg.ControlSocket); err != nil {
		return err
	}
	// Start the event stream listener before spawning the helper so it
	// can connect immediately.
	evtPath := helperEventSocketPath(cfg)
	es := NewEventStream(evtPath)
	esCtx, esCancel := context.WithCancel(context.Background())
	// The event socket is the primary push path for post-bootstrap session
	// deltas from the local helper to the daemon. If its listener fails to bind,
	// fail the whole bring-up here — BEFORE spawning the helper — rather than
	// silently starting in the slower DrainSessionDeltas polling fallback with a
	// non-nil-but-dead stream that takeoverReadyLocked would wave through as
	// healthy (#5273).
	if err := es.Start(esCtx); err != nil {
		esCancel()
		es.Close()
		return fmt.Errorf("start userspace dataplane event stream listener: %w", err)
	}
	m.eventStream = es
	m.eventStreamCancel = esCancel
	// Clear stale XSKMAP entries from previous helper instance.
	// Old entries point to dead socket fds; new helper will repopulate.
	if xskMap := m.bpfShim.Map(mapNameUserspaceXSK); xskMap != nil {
		for i := uint32(0); i < 4096; i++ {
			_ = xskMap.Delete(i)
		}
		slog.Debug("userspace: cleared stale XSKMAP entries")
	}
	// #9770: clear the previous incarnation's steering rows here — before the new
	// helper exists — instead of at the first ctrl enable, where live rows already
	// exist. See clearStaleSteeringRows for the quiescence proof.
	if deleted := clearStaleSteeringRows(m.bpfShim.Map(mapNameUserspaceSessions)); deleted > 0 {
		slog.Info("userspace: flushed stale BPF session entries at helper spawn",
			"deleted", deleted)
	}
	pollMode := effectivePollMode(cfg)
	cmd := exec.Command(binary,
		"--control-socket", cfg.ControlSocket,
		"--state-file", cfg.StateFile,
		"--workers", fmt.Sprintf("%d", cfg.Workers),
		"--ring-entries", fmt.Sprintf("%d", cfg.RingEntries),
		"--poll-mode", pollMode,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		if m.eventStreamCancel != nil {
			m.eventStreamCancel()
		}
		if m.eventStream != nil {
			m.eventStream.Close()
		}
		m.eventStream = nil
		m.eventStreamCancel = nil
		return fmt.Errorf("start userspace dataplane helper: %w", err)
	}
	m.cfg = cfg
	m.proc = cmd
	// #5838: one waiter per generation, started here and nowhere else. Until
	// this existed a helper that died AFTER reporting ready was never reaped,
	// never noticed, and left every `m.proc == nil` liveness test reading TRUE.
	m.startHelperSupervisorLocked(cmd)
	m.publishHAWatchdogSnapshotLocked()
	// Bootstrap XSK fill ring on all queues: send broadcast pings
	// 3 seconds after helper start. During this window, ctrl is disabled;
	// the shim only passes proven local/control traffic and drops transit.
	// The broadcast pings generate hardware RX events on multiple queues,
	// triggering NAPI which consumes fill ring entries and posts WQEs for
	// zero-copy.
	m.scheduleStartupNAPIBootstrapLocked()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.ControlSocket); err == nil {
			var status ProcessStatus
			if err := m.requestLocked(ControlRequest{Type: "ping"}, &status); err == nil {
				if status.PID != 0 || status.ConfigSnapshotProtocolVersion != 0 {
					m.setLastStatusLocked(status)
				}
				slog.Info("userspace dataplane helper started", "pid", cmd.Process.Pid, "socket", cfg.ControlSocket)
				return nil
			}
		}
		// #5838: ask the generation's WAITER whether the child is gone, not
		// cmd.ProcessState. ProcessState is written by cmd.Wait(), which now
		// runs on the supervisor goroutine, so reading it here would be a data
		// race — and before a waiter existed it was simply always nil, which is
		// why this early-out could never fire. The closed channel is the
		// race-free happens-before edge for the same question.
		if m.procSup != nil {
			select {
			case <-m.procSup.exited:
				// Read the disposition BEFORE the teardown: stopLocked clears
				// procSup, so reporting it afterwards would dereference nil.
				disposition := m.procSup.describeExit()
				slog.Error("userspace dataplane helper exited before becoming ready",
					"disposition", disposition)
				m.stopLocked()
				return fmt.Errorf("userspace dataplane helper exited before becoming ready at %s: %s",
					cfg.ControlSocket, disposition)
			default:
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	m.stopLocked()
	return fmt.Errorf("userspace dataplane helper did not become ready at %s", cfg.ControlSocket)
}

// tuneSocketBuffers raises the kernel socket buffer limits so AF_XDP copy-mode
// sockets can receive at line rate.  The default rmem_default (212992 = 208KB)
// is far too small — copy-mode XSK pushes each packet through the socket
// receive buffer and silently drops when it fills, causing throughput to stall
// after an initial burst.
func tuneSocketBuffers() {
	const desired = 67108864 // 64 MB
	paths := []string{
		"/proc/sys/net/core/rmem_default",
		"/proc/sys/net/core/rmem_max",
		"/proc/sys/net/core/wmem_default",
		"/proc/sys/net/core/wmem_max",
	}
	for _, path := range paths {
		cur, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var curVal int
		if _, err := fmt.Sscanf(strings.TrimSpace(string(cur)), "%d", &curVal); err != nil {
			continue
		}
		if curVal >= desired {
			continue
		}
		val := fmt.Sprintf("%d", desired)
		if err := os.WriteFile(path, []byte(val), 0644); err != nil {
			slog.Warn("failed to tune socket buffer", "path", path, "err", err)
		} else {
			slog.Info("tuned socket buffer for AF_XDP", "path", path, "from", curVal, "to", desired)
		}
	}
}

func findBinary(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit, nil
		}
		return "", fmt.Errorf("userspace dataplane binary not found: %s", explicit)
	}
	candidates := []string{
		"./xpf-userspace-dp",
		filepath.Join("userspace-dp", "target", "release", "xpf-userspace-dp"),
		filepath.Join(filepath.Dir(os.Args[0]), "xpf-userspace-dp"),
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	if p, err := exec.LookPath("xpf-userspace-dp"); err == nil {
		return p, nil
	}
	return "", errors.New("userspace dataplane helper binary not found; build make build-userspace-dp or configure system dataplane binary")
}

func (m *Manager) stopLocked() {
	// #5838 follow-up: retire this process generation FIRST — before the
	// `m.proc == nil` early return below, which is exactly the branch an
	// intentional stop takes when the helper has already crashed (the crash
	// path nils `m.proc` itself, so a stop after a crash reached NONE of the
	// teardown under that return).
	//
	// `restartHelperAfterCrash` fences its attempt on `m.procGen != gen`, and
	// before this bump a stop satisfied none of its three fences: it cleared
	// `m.proc` and `m.procSup` but left `m.procGen` and `m.helperCrash`
	// untouched. A crash whose backoff was still pending when the daemon shut
	// down therefore spawned a helper for a Manager that had been torn down —
	// after `Close()` that child outlives xpfd holding the NIC queues, the
	// EBUSY-on-zero-copy-queues collision the next start then hits — and the
	// restart chain kept re-arming afterwards.
	//
	// Only the GENERATION is retired here. `m.helperCrash` is deliberately NOT
	// cleared: `ensureProcessLocked` calls this same function when a spawn
	// fails its readiness wait, and the crash record is the retry debt that
	// path depends on (attempt count and backoff). Clearing it here would make
	// a failed restart forget it was retrying — see
	// TestRestartUsesTheCurrentConfigNotTheDeadGeneration5838, which pins that
	// debt. The bump is compatible with that path by construction: it already
	// re-fences its next attempt on whatever `m.procGen` reads after the failed
	// spawn.
	m.procGen++
	// Retire the helper-session epoch before teardown so a watchdog sender that
	// passed its snapshot check cannot reach this generation after the stop.
	// Do not wait on sessionMu here: explicit fail-closed disarm must happen
	// before any potentially slow session drain.
	m.haWatchdogProcessGen.Add(1)
	if m.eventStreamCancel != nil {
		m.eventStreamCancel()
		m.eventStreamCancel = nil
	}
	if m.eventStream != nil {
		m.eventStream.Close()
		m.eventStream = nil
	}
	if m.syncCancel != nil {
		m.syncCancel()
		m.syncCancel = nil
	}
	if m.proc == nil {
		m.sessionMu.Lock()
		m.sessionMu.Unlock()
		m.clearLastStatusLocked()
		m.bindingsBusySince = time.Time{}
		m.lastBindingsAutoRebind = time.Time{}
		m.consecutiveFailedAutoRebinds = 0
		m.sessionMirrorFailed = false
		m.sessionMirrorErr = ""
		m.helperHAStatePublished = false
		m.haWatchdogHelperInventory = nil
		m.haDegradedMu.Lock()
		clear(m.haDegradedCurrent)
		clear(m.haDegradedLastSent)
		m.haDegradedLastSentAt = 0
		m.haDegradedHaveLastSent = false
		m.haDegradedMu.Unlock()
		m.publishHAWatchdogSnapshotLocked()
		return
	}
	// Disable userspace forwarding BEFORE stopping the helper. Without this,
	// the XDP shim continues redirecting to XSK after the helper exits,
	// sending packets to dead socket fds. Setting ctrl.enabled=0 makes the
	// shim pass only proven local/control traffic and drop transit. If the
	// disable cannot be verified, the wrapper clears all bindings fail-closed
	// before the helper shutdown below (#5486).
	_ = m.disableCtrlBeforeTeardownLocked()
	m.sessionMu.Lock()
	m.sessionMu.Unlock()
	_ = m.requestLocked(ControlRequest{Type: "shutdown"}, nil)
	// The waiter started at spawn owns this child's Wait. Waiting on ITS
	// completion — rather than launching a second cmd.Wait() here, which is
	// what this code used to do — is what makes "exactly one Wait per
	// generation" true; two waiters race and one of them gets ECHILD.
	//
	// Blocking on it while holding m.mu is safe because superviseHelper closes
	// exited BEFORE it acquires m.mu.
	done := m.helperExitedChanLocked()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		if m.proc.Process != nil {
			_ = m.proc.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			if m.proc.Process != nil {
				_ = m.proc.Process.Kill()
			}
			<-done
		}
	}
	m.proc = nil
	m.procSup = nil
	m.resetAfterHelperGoneLocked()
}

// helperExitedChanLocked returns the channel the current generation's waiter
// closes when the child is reaped. A generation with no supervisor record
// cannot happen for a running helper (startHelperSupervisorLocked runs under
// the same lock as the m.proc assignment), but returning an already-closed
// channel keeps a teardown from blocking forever if it ever did.
func (m *Manager) helperExitedChanLocked() chan struct{} {
	if m.procSup != nil {
		return m.procSup.exited
	}
	ch := make(chan struct{})
	close(ch)
	return ch
}

// resetAfterHelperGoneLocked clears every piece of manager state that describes
// a helper which is no longer running.
//
// It is shared by the intentional teardown (stopLocked) and the crash path
// (handleUnexpectedHelperExitLocked) precisely so the two cannot drift about
// WHICH state a departed helper invalidates. A crash that cleared less than a
// stop would leave exactly the stale readiness the issue is about; before this
// existed the crash path cleared nothing at all.
func (m *Manager) resetAfterHelperGoneLocked() {
	if m.eventStreamCancel != nil {
		m.eventStreamCancel()
		m.eventStreamCancel = nil
	}
	if m.eventStream != nil {
		m.eventStream.Close()
		m.eventStream = nil
	}
	if m.syncCancel != nil {
		m.syncCancel()
		m.syncCancel = nil
	}
	m.clearLastStatusLocked()
	m.neighborsPrewarmed = false
	m.ctrlEnableAt = time.Time{}
	m.xskLivenessProven = false
	m.xskLivenessFailed = false
	m.initialCtrlCleanupDone = false
	m.xskProbeStart = time.Time{}
	m.lastXSKRX = 0
	m.lastNAPIBootstrap = time.Time{}
	m.lastStandbyNeighResolve = time.Time{}
	m.bindingsBusySince = time.Time{}
	m.lastBindingsAutoRebind = time.Time{}
	m.consecutiveFailedAutoRebinds = 0
	m.publishedSnapshot = 0
	// #7465: a new helper starts with an EMPTY HA inventory, so the fact that the
	// previous process had been told says nothing about this one. Without this
	// clear the arm gate would pass on a restarted helper that has never been
	// sent an inventory — the exact state it exists to refuse.
	m.helperHAStatePublished = false
	m.haWatchdogHelperInventory = nil
	// A restarted helper has a new empty inventory; discard the degraded
	// watchdog throttle baseline so the next published capability cannot inherit
	// the old process's receipt.
	m.haDegradedMu.Lock()
	clear(m.haDegradedCurrent)
	clear(m.haDegradedLastSent)
	m.haDegradedLastSentAt = 0
	m.haDegradedHaveLastSent = false
	m.haDegradedMu.Unlock()
	m.publishedPlanKey = ""
	// #2079: forget the applied snapshot when the helper stops so a
	// restarted helper does not expose a stale applied config before its
	// first apply lands (AppliedNATView also guards on m.proc == nil).
	m.appliedSnapshot = appliedSnapshot{}
	m.sessionMirrorFailed = false
	m.sessionMirrorErr = ""
	m.publishHAWatchdogSnapshotLocked()
}

// processRestartRequiredDuringStartup reports whether a config applied during
// the pending-XSK-startup window changes the helper's PROCESS IDENTITY and
// therefore needs a restart that the binding-plan key cannot ask for (#8899).
//
// It exists as a named function rather than an inline `&&` so the production
// path and its guard call the SAME predicate. A cell that re-derives this
// expression would verify the arithmetic and not the wiring.
func processRestartRequiredDuringStartup(
	pendingXSKStartup bool,
	running config.UserspaceConfig,
	desired config.UserspaceConfig,
) bool {
	return pendingXSKStartup && !configEqual(running, desired)
}

// effectivePollMode is the value that actually reaches the helper's argv.
// `--poll-mode` is passed unconditionally and an empty configured value is
// defaulted at spawn (see ensureProcessLocked), so "" and "busy-poll" produce
// the IDENTICAL child process.
//
// #8899: comparing the raw strings therefore reports a difference where none
// exists on the wire — an operator explicitly writing the default they were
// already running would be told the process identity changed. That was
// harmless while the comparison only guarded the normal apply path, which
// re-execs anyway; the startup-window trigger makes it a spurious RESTART, so
// the two spellings are normalised at the one place both paths consult.
func effectivePollMode(c config.UserspaceConfig) string {
	if c.PollMode == "" {
		return defaultPollMode
	}
	return c.PollMode
}

// helperSpawnIdentity is what the helper process IS: the exact set of values
// `ensureProcessLocked` puts on its command line and binds its sockets to,
// AFTER every default has been resolved.
//
// #8899: two of these fields have resolvers and the comparison used the RAW
// value for both, so writing a default down explicitly compared unequal while
// producing an identical child. `PollMode` was found by review and fixed;
// `EventSocket` was the same defect one field over and the fix did not
// generalise to it, because nothing tied the comparison to the resolution.
//
// This type is that tie. `configEqual` is defined AS identity equality, so a
// field can no longer be compared by a different rule than the one the spawn
// path applies — the two cannot drift, rather than being checked for drift.
// A new argv field is added here once and both sides follow.
type helperSpawnIdentity struct {
	binary        string
	controlSocket string
	eventSocket   string
	stateFile     string
	pollMode      string
	workers       int
	ringEntries   int
}

// helperSpawnIdentityOf resolves a config to the process it would spawn.
// Every field here is read from the same helper the spawn path uses.
func helperSpawnIdentityOf(c config.UserspaceConfig) helperSpawnIdentity {
	return helperSpawnIdentity{
		binary:        c.Binary,
		controlSocket: c.ControlSocket,
		eventSocket:   helperEventSocketPath(c),
		stateFile:     c.StateFile,
		pollMode:      effectivePollMode(c),
		workers:       c.Workers,
		ringEntries:   c.RingEntries,
	}
}

func configEqual(a, b config.UserspaceConfig) bool {
	return helperSpawnIdentityOf(a) == helperSpawnIdentityOf(b)
}

func (m *Manager) StartFIBSync(ctx context.Context) {
	m.bpfShim.StartFIBSync(ctx)
}
