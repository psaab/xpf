package userspace

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (m *Manager) ensureProcessLocked(cfg config.UserspaceConfig) error {
	tuneSocketBuffers()
	if m.proc != nil && m.proc.Process != nil && configEqual(m.cfg, cfg) {
		if err := m.requestLocked(ControlRequest{Type: "ping"}, nil); err == nil {
			return nil
		}
		slog.Warn("userspace dataplane helper unhealthy, restarting")
		m.stopLocked()
	}
	if m.proc != nil {
		m.stopLocked()
	}
	m.lastStatus = ProcessStatus{}
	binary, err := findBinary(cfg.Binary)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ControlSocket), 0755); err != nil {
		return fmt.Errorf("mkdir control socket dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.StateFile), 0755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	_ = os.Remove(cfg.ControlSocket)
	// Start the event stream listener before spawning the helper so it
	// can connect immediately.
	evtPath := cfg.EventSocket
	if evtPath == "" {
		evtPath = filepath.Join(filepath.Dir(cfg.ControlSocket), "userspace-dp-events.sock")
	}
	_ = os.Remove(evtPath)
	es := NewEventStream(evtPath)
	esCtx, esCancel := context.WithCancel(context.Background())
	es.Start(esCtx)
	m.eventStream = es
	m.eventStreamCancel = esCancel
	// Clear stale XSKMAP entries from previous helper instance.
	// Old entries point to dead socket fds; new helper will repopulate.
	if xskMap := m.inner.Map("userspace_xsk_map"); xskMap != nil {
		for i := uint32(0); i < 4096; i++ {
			_ = xskMap.Delete(i)
		}
		slog.Debug("userspace: cleared stale XSKMAP entries")
	}
	pollMode := cfg.PollMode
	if pollMode == "" {
		pollMode = "busy-poll"
	}
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
	// Bootstrap XSK fill ring on all queues: send broadcast pings
	// 3 seconds after helper start. During this window, ctrl is disabled
	// so the XDP shim falls back to eBPF. The broadcast pings generate
	// hardware RX events on multiple queues, triggering NAPI which
	// consumes fill ring entries and posts WQEs for zero-copy.
	go func() {
		time.Sleep(3 * time.Second)
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.proc == nil {
			return
		}
		m.bootstrapNAPIQueuesAsyncLocked("startup")
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.ControlSocket); err == nil {
			if err := m.requestLocked(ControlRequest{Type: "ping"}, nil); err == nil {
				slog.Info("userspace dataplane helper started", "pid", cmd.Process.Pid, "socket", cfg.ControlSocket)
				return nil
			}
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			break
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

func (m *Manager) requestDetailedLocked(req ControlRequest) (ControlResponse, error) {
	if m.cfg.ControlSocket == "" {
		return ControlResponse{}, errors.New("userspace dataplane control socket not configured")
	}
	conn, err := net.DialTimeout("unix", m.cfg.ControlSocket, 2*time.Second)
	if err != nil {
		return ControlResponse{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return ControlResponse{}, err
	}
	var resp ControlResponse
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return ControlResponse{}, err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unknown helper error"
		}
		return ControlResponse{}, errors.New(resp.Error)
	}
	return resp, nil
}

// sessionSocketPath returns the path to the dedicated session sync socket.
func (m *Manager) sessionSocketPath() string {
	if m.cfg.ControlSocket == "" {
		return ""
	}
	dir := filepath.Dir(m.cfg.ControlSocket)
	return filepath.Join(dir, "userspace-dp-sessions.sock")
}

// requestSessionSync sends a session sync request via the dedicated session
// socket, using sessionMu instead of mu. This ensures session installs from
// HA sync never block behind snapshot publishes on the main control socket.
func (m *Manager) requestSessionSync(req ControlRequest) error {
	sockPath := m.sessionSocketPath()
	if sockPath == "" {
		return errors.New("session socket not configured")
	}
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return err
	}
	var resp ControlResponse
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unknown helper error"
		}
		return errors.New(resp.Error)
	}
	return nil
}

func (m *Manager) syncSnapshotLocked() error {
	if m.proc == nil || m.proc.Process == nil || m.lastSnapshot == nil {
		return nil
	}
	planKey := snapshotBindingPlanKey(m.lastSnapshot)
	if m.publishedSnapshot >= m.lastSnapshot.Generation {
		return nil
	}
	if m.lastStatus.LastSnapshotGeneration >= m.lastSnapshot.Generation {
		// #1197 v7 (Codex code-review v6): status-loop catch-up
		// path. Helper has the snapshot; mirror the FULL
		// successful-apply_snapshot bookkeeping, otherwise
		// downstream paths see stale publishedPlanKey /
		// lastSnapshotHash and may force unnecessary refreshes
		// or break the same-plan-during-XSK-startup exception.
		hash, hashOK := snapshotContentHash(m.lastSnapshot)
		m.publishedSnapshot = m.lastSnapshot.Generation
		m.publishedPlanKey = planKey
		if hashOK {
			m.lastSnapshotHash = hash
		}
		m.rebuildNeighborIndex()
		m.rebuildMonitoredIfindexes()
		return nil
	}
	// Publish the initial snapshot immediately so the helper can plan its
	// bindings. After that, defer newer snapshots until the first XSK
	// liveness outcome is known. HA startup can emit several snapshots in
	// quick succession as VIPs and routes converge; pushing every one of
	// them forces back-to-back full AF_XDP reconciles and self-collides.
	//
	// EXCEPTION: allow same-plan refreshes (FIB-only updates) through even
	// during XSK startup. These don't trigger XSK rebinding — they only
	// update routes and neighbors. Blocking them creates a deadlock: XSK
	// liveness needs RX traffic, but transit traffic needs FIB data that
	// hasn't been published yet.
	if m.publishedSnapshot != 0 && !m.xskLivenessProven && !m.xskLivenessFailed {
		samePlan := m.publishedPlanKey != "" && m.publishedPlanKey == planKey
		if !samePlan {
			return nil
		}
		slog.Info("userspace: publishing deferred same-plan snapshot during XSK startup",
			"generation", m.lastSnapshot.Generation,
			"fib_generation", m.lastSnapshot.FIBGeneration,
			"published", m.publishedSnapshot)
	}
	if m.publishedSnapshot != 0 && m.publishedPlanKey != "" && m.publishedPlanKey != planKey {
		slog.Info(
			"userspace: restarting helper for binding plan change",
			"generation", m.lastSnapshot.Generation,
			"fib_generation", m.lastSnapshot.FIBGeneration,
		)
		cfg := m.cfg
		m.stopLocked()
		if err := m.ensureProcessLocked(cfg); err != nil {
			return fmt.Errorf("restart userspace helper for binding plan change: %w", err)
		}
	}
	// Content-hash dedup: skip the control socket publish if the snapshot's
	// forwarding-relevant content hasn't changed since the last publish.
	// This eliminates redundant publishes during route convergence where
	// BumpFIBGeneration fires repeatedly but routes/neighbors are unchanged.
	hash, hashOK := snapshotContentHash(m.lastSnapshot)
	if hashOK && hash == m.lastSnapshotHash && m.publishedSnapshot != 0 {
		// Still update the published generation so subsequent checks pass.
		m.publishedSnapshot = m.lastSnapshot.Generation
		return nil
	}
	// #1197 v5 (Codex code-review v4 #2): publishable-only filter
	// for parity with update_neighbors path.
	publishSnap := *m.lastSnapshot
	publishSnap.Neighbors = filterPublishableNeighbors(m.lastSnapshot.Neighbors)
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: &publishSnap}, &status); err != nil {
		return fmt.Errorf("publish userspace snapshot: %w", err)
	}
	// #1197 v5 (Codex code-review v4 #1): rebuild listener
	// caches AFTER successful publish on the deferred-publish
	// path too. Compile() defers when XSK is starting up; this
	// is where the snapshot actually lands in userspace-dp.
	m.rebuildNeighborIndex()
	m.rebuildMonitoredIfindexes()
	m.publishedSnapshot = m.lastSnapshot.Generation
	m.publishedPlanKey = planKey
	if hashOK {
		m.lastSnapshotHash = hash
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return fmt.Errorf("sync helper status: %w", err)
	}
	return nil
}

func (m *Manager) requestLocked(req ControlRequest, status *ProcessStatus) error {
	resp, err := m.requestDetailedLocked(req)
	if err != nil {
		return err
	}
	if status != nil && resp.Status != nil {
		*status = *resp.Status
	}
	return nil
}

func (m *Manager) ensureStatusLoopLocked() {
	if m.syncCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.syncCancel = cancel
	go m.statusLoop(ctx)
}

func (m *Manager) statusLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			if m.proc == nil {
				m.mu.Unlock()
				return
			}
			prevActiveSig := activeHAGroupSignature(m.haGroups)
			var status ProcessStatus
			if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err == nil {
				if err := m.applyHelperStatusLocked(&status); err != nil {
					slog.Warn("userspace dataplane status sync failed", "err", err)
				} else {
					// Bindings watchdog (#473): verify the BPF map matches
					// the helper's reported state. Only run after a successful
					// status update — stale m.lastStatus could cause incorrect
					// repairs.
					repaired := m.verifyBindingsMapLocked()
					m.maybeAutoRebindBusyBindingsLocked(time.Now(), repaired)
				}
				if m.lastSnapshot != nil && m.publishedSnapshot < m.lastSnapshot.Generation {
					if err := m.syncSnapshotLocked(); err != nil {
						slog.Warn("userspace dataplane snapshot sync failed", "err", err)
					}
				}
				helperActiveSig := activeHAGroupSignatureSlice(status.HAGroups)
				if m.clusterHA {
					_ = m.refreshHAStateFromMapsLocked()
				}
				newActiveSig := activeHAGroupSignature(m.haGroups)
				if m.clusterHA && newActiveSig != "" && time.Since(m.lastRGActivateTime) >= 2*time.Second {
					// Only sync watchdog updates to the helper from the poll.
					// Do NOT sync active/inactive transitions here — that's
					// handled by UpdateRGActive which must be the sole source
					// of demotion/activation deltas. If the poll syncs first,
					// the helper sees no delta and skips FlushFlowCaches.
					// Skip entirely for 2s after UpdateRGActive to avoid
					// control socket contention during post-transition work.
					if helperActiveSig != newActiveSig || newActiveSig != prevActiveSig {
						// Sync watchdog timestamps only (HA state update
						// without active/inactive change detection).
						// Throttle to every 5s to avoid control socket
						// contention with session installs during bulk sync.
						if time.Since(m.lastHASyncTime) >= 5*time.Second {
							if err := m.syncHAWatchdogOnlyLocked(); err != nil {
								slog.Warn("userspace dataplane HA watchdog sync failed", "err", err)
							}
							m.lastHASyncTime = time.Now()
						}
					}
					// Do not bootstrap NAPI queues or kick neighbor repair on
					// HA ownership changes. By the time UpdateRGActive runs, the
					// standby must already be forwarding-ready; otherwise
					// TakeoverReady() should have blocked the handoff earlier.
				}
				if err := m.syncDesiredForwardingStateLocked(); err != nil {
					slog.Warn("userspace dataplane forwarding sync failed", "err", err)
				}
			} else {
				slog.Warn("userspace dataplane status poll failed", "err", err)
			}
			// Keep the targeted kernel prewarm during initial startup. After
			// startup, continue a throttled standby-only neighbor prewarm so HA
			// standby nodes already have WAN next-hop resolution before the
			// first redirected packets arrive.
			now := time.Now()
			if now.Sub(startTime) < 60*time.Second && m.lastSnapshot != nil && m.lastSnapshot.Config != nil {
				m.proactiveNeighborResolveAsyncLocked()
			} else if m.shouldStandbyNeighborPrewarmLocked(now) {
				m.lastStandbyNeighResolve = now
				m.proactiveNeighborResolveAsyncLocked()
			}
			m.mu.Unlock()
		}
	}
}

func (m *Manager) shouldStandbyNeighborPrewarmLocked(now time.Time) bool {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return false
	}
	if !m.clusterHA || !m.configHasDataRGLocked() || m.hasActiveDataRGLocked() {
		return false
	}
	if m.proc == nil || m.proc.Process == nil {
		return false
	}
	if !m.lastStatus.Enabled || !m.lastStatus.ForwardingArmed || !m.lastStatus.Capabilities.ForwardingSupported {
		return false
	}
	if !m.lastStandbyNeighResolve.IsZero() && now.Sub(m.lastStandbyNeighResolve) < 10*time.Second {
		return false
	}
	return true
}

func (m *Manager) bootstrapNAPIQueuesAsyncLocked(reason string) {
	now := time.Now()
	if !m.lastNAPIBootstrap.IsZero() && now.Sub(m.lastNAPIBootstrap) < 2*time.Second {
		return
	}
	m.lastNAPIBootstrap = now
	go func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.proc == nil || m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
			return
		}
		slog.Info("userspace: bootstrapping NAPI queues", "reason", reason)
		m.bootstrapNAPIQueuesLocked()
	}()
}

func (m *Manager) stopLocked() {
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
		m.lastStatus = ProcessStatus{}
		m.bindingsBusySince = time.Time{}
		m.lastBindingsAutoRebind = time.Time{}
		m.sessionMirrorFailed = false
		m.sessionMirrorErr = ""
		return
	}
	// Disable userspace forwarding BEFORE stopping the helper.
	// Without this, the XDP shim continues redirecting to XSK after
	// the helper exits, sending packets to dead socket fds. Setting
	// ctrl.enabled=0 makes the shim fall back to the eBPF pipeline.
	m.disableUserspaceCtrlLocked()
	_ = m.requestLocked(ControlRequest{Type: "shutdown"}, nil)
	done := make(chan struct{})
	go func(cmd *exec.Cmd) {
		_ = cmd.Wait()
		close(done)
	}(m.proc)
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
	m.lastStatus = ProcessStatus{}
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
	m.publishedSnapshot = 0
	m.publishedPlanKey = ""
	m.sessionMirrorFailed = false
	m.sessionMirrorErr = ""
}

// bootstrapNAPIQueuesLocked sends UDP probe packets to each managed
// interface to trigger hardware RX events on all NIC queues. This is
// needed for mlx5 zero-copy: the driver only consumes XSK fill ring
// entries during NAPI poll, and NAPI only runs when there are HW RX
// events. Without at least one packet per queue, the fill ring stays
// unconsumed and XDP_REDIRECT silently drops packets.
//
// The probes are sent while ctrl is disabled, so the XDP shim falls
// back to the eBPF pipeline which handles them normally (XDP_PASS).
func (m *Manager) bootstrapNAPIQueuesLocked() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	// Send UDP probes and an ICMP echo on each managed interface to create
	// hardware RX events and neighbor resolution. This triggers mlx5 NAPI,
	// which processes the XSK fill ring and posts WQEs for zero-copy packet
	// reception. Without at least one HW RX event per queue, the fill ring
	// entries added after socket bind are never consumed by the driver's pool.
	for _, linuxName := range userspaceBootstrapProbeInterfaces(m.lastSnapshot.Config) {
		// Send many parallel pings to hit all RSS queues. Each ping
		// process gets a different ICMP echo ID from the kernel, causing
		// RSS to distribute replies across different NIC queues. This
		// triggers NAPI on each queue, which posts fill ring WQEs for
		// zero-copy XSK packet reception.
		link, err := netlink.LinkByName(linuxName)
		if err != nil || link == nil {
			continue
		}
		// Find a target: gateway or any neighbor
		var target string
		routes, _ := netlink.RouteList(link, netlink.FAMILY_V4)
		for _, r := range routes {
			if r.Gw != nil && r.Gw.To4() != nil {
				target = r.Gw.String()
				break
			}
		}
		if target == "" {
			neighs, _ := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
			for _, n := range neighs {
				if n.IP != nil && n.IP.To4() != nil && n.HardwareAddr != nil &&
					n.State != netlink.NUD_FAILED {
					target = n.IP.String()
					break
				}
			}
		}
		if target == "" {
			continue
		}
		// Send multiple ICMP probes with different ICMP echo IDs to
		// trigger NAPI on ALL NIC queues. mlx5 RSS distributes replies
		// across queues based on hash(src, dst, proto, id). Sending
		// ~2× the queue count with varying IDs makes it very likely
		// that every queue sees at least one hardware RX event, which
		// posts XSK fill ring WQEs for zero-copy packet reception.
		targetIP := net.ParseIP(target)
		if targetIP != nil {
			// ICMP RSS hashes on (src, dst, proto) only — varying
			// ICMP ID doesn't change the target queue. Use UDP probes
			// with varying ports: mlx5 RSS hashes (src, dst, sport,
			// dport) for UDP, distributing across all queues.
			// Send 30 probes across port range 40000-40029.
			for i := 0; i < 30; i++ {
				sendUDPProbeForNAPI(linuxName, targetIP, uint16(40000+i))
				if i%6 == 5 {
					time.Sleep(time.Millisecond)
				}
			}
			// Also send one ICMP probe for neighbor resolution.
			sendICMPProbeFromManager(linuxName, targetIP)
		}
	}
}

// proactiveNeighborResolveLocked reads the kernel neighbor table and
// pings any STALE/FAILED entries to force re-resolution. Also pings
// the default gateway on each managed interface. This ensures the
// helper has fresh neighbor entries when ctrl is enabled.
func (m *Manager) proactiveNeighborResolveLocked() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	// Collect all managed interface names
	seen := make(map[string]bool)
	var ifaces []string
	for ifName, ifc := range m.lastSnapshot.Config.Interfaces.Interfaces {
		base := config.LinuxIfName(ifName)
		if !seen[base] {
			seen[base] = true
			ifaces = append(ifaces, base)
		}
		for _, unit := range ifc.Units {
			if unit.VlanID > 0 {
				vlanName := fmt.Sprintf("%s.%d", base, unit.VlanID)
				if !seen[vlanName] {
					seen[vlanName] = true
					ifaces = append(ifaces, vlanName)
				}
			}
		}
	}
	// For each interface, read neighbors and ping any that need resolution
	var resolved int
	for _, ifName := range ifaces {
		link, err := netlink.LinkByName(ifName)
		if err != nil || link == nil {
			continue
		}
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			neighs, err := netlink.NeighList(link.Attrs().Index, family)
			if err != nil {
				continue
			}
			for _, n := range neighs {
				if n.IP == nil || n.IP.IsLinkLocalUnicast() {
					continue
				}
				// Trigger ARP/NDP resolution for STALE/FAILED/absent entries.
				if n.HardwareAddr == nil || len(n.HardwareAddr) == 0 ||
					n.State == netlink.NUD_STALE || n.State == netlink.NUD_DELAY ||
					n.State == netlink.NUD_PROBE || n.State == netlink.NUD_FAILED {
					sendICMPProbeFromManager(ifName, n.IP)
					resolved++
				}
			}
		}
	}
	// Also resolve route next-hops that aren't in the neighbor table yet.
	// After VRRP election, the kernel may not have ARP for destinations
	// like .200 that were previously known but got purged on restart.
	routes, _ := netlink.RouteList(nil, netlink.FAMILY_ALL)
	for _, r := range routes {
		if r.Gw == nil || r.Gw.IsLinkLocalUnicast() {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil || link == nil {
			continue
		}
		ifName := link.Attrs().Name
		if !seen[ifName] {
			continue // only managed interfaces
		}
		// Check if this gateway is already in neighbor table
		existing, _ := netlink.NeighList(r.LinkIndex, netlink.FAMILY_ALL)
		found := false
		for _, n := range existing {
			if n.IP.Equal(r.Gw) && n.HardwareAddr != nil && len(n.HardwareAddr) > 0 &&
				n.State != netlink.NUD_FAILED {
				found = true
				break
			}
		}
		if !found {
			sendICMPProbeFromManager(ifName, r.Gw)
			resolved++
		}
	}
	if resolved > 0 {
		slog.Info("userspace: proactive neighbor resolution",
			"resolved", resolved, "interfaces", len(ifaces))
	}
}

// sendICMPProbeFromManager sends a single raw ICMP/ICMPv6 echo request
// bound to the given interface. Triggers kernel ARP/NDP resolution
// without shelling out to ping. Non-blocking.
func sendICMPProbeFromManager(iface string, target net.IP) {
	sendICMPProbeWithID(iface, target, 0)
}

// sendICMPProbeWithID sends a single ICMP echo request with a specific echo
// ID. Varying the ID causes RSS to distribute replies across different NIC
// queues, triggering NAPI on each queue for zero-copy fill ring processing.
func sendICMPProbeWithID(iface string, target net.IP, id uint16) {
	if target.To4() != nil {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		// ICMP Echo: type=8, code=0, checksum(auto), id, seq=1
		icmp := [8]byte{8, 0, 0, 0, byte(id >> 8), byte(id), 0, 1}
		// Compute checksum
		var sum uint32
		for i := 0; i < 8; i += 2 {
			sum += uint32(icmp[i])<<8 | uint32(icmp[i+1])
		}
		sum = (sum >> 16) + (sum & 0xffff)
		sum += sum >> 16
		cs := uint16(^sum)
		icmp[2] = byte(cs >> 8)
		icmp[3] = byte(cs)
		sa := &unix.SockaddrInet4{}
		copy(sa.Addr[:], target.To4())
		_ = unix.Sendto(fd, icmp[:], unix.MSG_DONTWAIT, sa)
	} else {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_ICMPV6, unix.IPV6_CHECKSUM, 2)
		// ICMPv6 Echo: type=128, code=0, checksum(kernel), id, seq=1
		icmp6 := [8]byte{128, 0, 0, 0, byte(id >> 8), byte(id), 0, 1}
		sa6 := &unix.SockaddrInet6{}
		copy(sa6.Addr[:], target.To16())
		_ = unix.Sendto(fd, icmp6[:], unix.MSG_DONTWAIT, sa6)
	}
}

// sendUDPProbeForNAPI sends a single UDP packet to the target on the given
// port. The packet is sent via a raw UDP socket bound to the interface.
// The destination is unlikely to respond, but the important thing is that
// the REPLY (ICMP port unreachable) or even the outgoing packet's DMA
// completion triggers NAPI on the NIC queue determined by RSS hash of
// (src_ip, dst_ip, src_port, dst_port). Different ports → different queues.
func sendUDPProbeForNAPI(iface string, target net.IP, port uint16) {
	if target.To4() != nil {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		sa := &unix.SockaddrInet4{Port: int(port)}
		copy(sa.Addr[:], target.To4())
		_ = unix.Sendto(fd, []byte("napi"), unix.MSG_DONTWAIT, sa)
	} else {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		sa6 := &unix.SockaddrInet6{Port: int(port)}
		copy(sa6.Addr[:], target.To16())
		_ = unix.Sendto(fd, []byte("napi"), unix.MSG_DONTWAIT, sa6)
	}
}

// proactiveNeighborResolveAsyncLocked is the non-blocking version that
// fires probes in background goroutines. Used by the status loop.
func (m *Manager) proactiveNeighborResolveAsyncLocked() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	cfg := m.lastSnapshot.Config
	go proactiveNeighborResolveAsync(cfg)
}

type neighborProbeTarget struct {
	iface string
	ip    string
}

func proactiveNeighborResolveAsync(cfg *config.Config) {
	seen := make(map[string]bool)
	targetSet := make(map[string]struct{})
	var targets []neighborProbeTarget
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		base := config.LinuxIfName(ifName)
		seen[base] = true // include base interface for route-GW probing
		for _, unit := range ifc.Units {
			linuxName := base
			if unit.VlanID > 0 {
				linuxName = fmt.Sprintf("%s.%d", base, unit.VlanID)
			}
			seen[linuxName] = true
			link, err := netlink.LinkByName(linuxName)
			if err != nil || link == nil {
				continue
			}
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				neighs, err := netlink.NeighList(link.Attrs().Index, family)
				if err != nil {
					continue
				}
				for _, n := range neighs {
					if n.IP == nil || n.IP.IsLinkLocalUnicast() {
						continue
					}
					if n.HardwareAddr == nil || len(n.HardwareAddr) == 0 ||
						n.State == netlink.NUD_STALE || n.State == netlink.NUD_FAILED {
						key := linuxName + "|" + n.IP.String()
						if _, ok := targetSet[key]; ok {
							continue
						}
						targetSet[key] = struct{}{}
						targets = append(targets, neighborProbeTarget{iface: linuxName, ip: n.IP.String()})
					}
				}
			}
		}
	}
	routes, _ := netlink.RouteList(nil, netlink.FAMILY_ALL)
	for _, r := range routes {
		if r.Gw == nil || r.Gw.IsLinkLocalUnicast() {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil || link == nil {
			continue
		}
		ifName := link.Attrs().Name
		if !seen[ifName] {
			continue
		}
		existing, _ := netlink.NeighList(r.LinkIndex, netlink.FAMILY_ALL)
		found := false
		for _, n := range existing {
			if n.IP.Equal(r.Gw) && n.HardwareAddr != nil && len(n.HardwareAddr) > 0 &&
				n.State != netlink.NUD_FAILED {
				found = true
				break
			}
		}
		if found {
			continue
		}
		key := ifName + "|" + r.Gw.String()
		if _, ok := targetSet[key]; ok {
			continue
		}
		targetSet[key] = struct{}{}
		targets = append(targets, neighborProbeTarget{iface: ifName, ip: r.Gw.String()})
	}
	for _, t := range targets {
		go func(iface, ip string) {
			targetIP := net.ParseIP(ip)
			if targetIP != nil {
				sendICMPProbeFromManager(iface, targetIP)
			}
		}(t.iface, t.ip)
	}
}

// disableUserspaceCtrlLocked sets ctrl.enabled=0 in the BPF map so the XDP
// shim stops redirecting packets to XSK. This MUST be called before the
// helper exits to prevent packets being sent to dead socket fds.
func (m *Manager) disableUserspaceCtrlLocked() {
	ctrlMap := m.inner.Map("userspace_ctrl")
	if ctrlMap == nil {
		return
	}
	zero := uint32(0)
	// Read current ctrl, set enabled=0, write back.
	var ctrl userspaceCtrlValue
	if err := ctrlMap.Lookup(zero, &ctrl); err != nil {
		return
	}
	ctrl.Enabled = 0
	_ = ctrlMap.Update(zero, ctrl, ebpf.UpdateAny)
	slog.Info("userspace: disabled ctrl (helper stopping)")
}

// reEnableUserspaceCtrlLocked sets ctrl.enabled=1 in the BPF map.
// Used to rollback a ctrl disable when the subsequent operation fails.
func (m *Manager) reEnableUserspaceCtrlLocked() {
	ctrlMap := m.inner.Map("userspace_ctrl")
	if ctrlMap == nil {
		return
	}
	zero := uint32(0)
	var ctrl userspaceCtrlValue
	if err := ctrlMap.Lookup(zero, &ctrl); err != nil {
		return
	}
	ctrl.Enabled = 1
	_ = ctrlMap.Update(zero, ctrl, ebpf.UpdateAny)
	slog.Info("userspace: re-enabled ctrl (rollback)")
}

// DisableAndStopHelper disables ctrl and swaps to the eBPF pipeline entry
// program. This prevents the XDP shim from redirecting new packets to XSK.
// Must be called BEFORE any operation that invalidates UMEM (e.g. link
// DOWN on mlx5 zero-copy). Worker threads keep running but see no new
// packets since ctrl=0 stops XSK redirects.
//
// Deprecated: use PrepareLinkCycle which also stops the Rust workers.
func (m *Manager) DisableAndStopHelper() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	m.disableUserspaceCtrlLocked()
	// Swap to eBPF pipeline so packets go through xdp_main_prog
	// even if the XDP shim was previously attached.
	if m.inner.XDPEntryProg != "xdp_main_prog" {
		_ = m.inner.SwapXDPEntryProg("xdp_main_prog")
	}
}

// PrepareLinkCycle must be called BEFORE any link DOWN/UP cycle (e.g. RETH
// MAC programming). It:
//  1. Disables ctrl so the XDP shim stops redirecting to XSK
//  2. Swaps to xdp_main_prog (eBPF pipeline)
//  3. Sends "stop_workers" to the Rust helper, which joins all worker
//     threads — no thread touches UMEM after this returns
//
// The caller then performs the link DOWN/UP. Afterwards, NotifyLinkCycle
// sends "rebind" to recreate workers with fresh AF_XDP sockets.
func (m *Manager) PrepareLinkCycle() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	m.disableUserspaceCtrlLocked()
	if m.inner.XDPEntryProg != "xdp_main_prog" {
		_ = m.inner.SwapXDPEntryProg("xdp_main_prog")
	}
	// Tell the Rust helper to stop all workers. This joins worker
	// threads so they stop touching UMEM before the NIC unmaps pages
	// during link DOWN.
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "stop_workers"}, &status); err != nil {
		slog.Warn("userspace: stop_workers before link cycle failed", "err", err)
		return
	}
	slog.Info("userspace: workers stopped before link cycle",
		"bindings", len(status.Bindings))
}

func configEqual(a, b config.UserspaceConfig) bool {
	return a.Binary == b.Binary &&
		a.ControlSocket == b.ControlSocket &&
		a.EventSocket == b.EventSocket &&
		a.StateFile == b.StateFile &&
		a.Workers == b.Workers &&
		a.RingEntries == b.RingEntries &&
		a.PollMode == b.PollMode
}

func (m *Manager) StartFIBSync(ctx context.Context) {
	m.inner.StartFIBSync(ctx)
}

// NotifyLinkCycle tells the userspace helper to rebind all AF_XDP sockets.
// In mlx5 (and other drivers), a link DOWN/UP cycle destroys the kernel-side
// XSK receive queue.  The sockets remain open but no longer receive packets.
// This is called after programRethMAC which takes RETH interfaces DOWN/UP.
//
// PrepareLinkCycle should have been called BEFORE the link cycle to stop
// workers (so they don't access UMEM during link DOWN). This method
// waits 200ms for NIC reinitialization then sends "rebind" to recreate
// workers with fresh AF_XDP sockets.
//
// The 200ms delay lets the mlx5 NIC fully reinitialize its UMR (User
// Memory Region) subsystem after link reactivation. Without this, the
// NIC's UMR WQE queue overflows when all XSK sockets are recreated
// simultaneously (rx_xsk_congst_umr), causing UMEM pages to not be mapped
// and packets to be silently dropped despite successful XDP_REDIRECT.
func (m *Manager) NotifyLinkCycle() {
	// Let the NIC fully tear down XSK zero-copy contexts before recreating
	// sockets. mlx5 releases zero-copy queue resources asynchronously after
	// socket close — binding a new socket to the same queue before teardown
	// completes returns EBUSY. 1s gives the driver ample time.
	time.Sleep(1 * time.Second)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	// Ensure ctrl is disabled (PrepareLinkCycle should have done this,
	// but guard against callers that skip it).
	m.disableUserspaceCtrlLocked()
	if m.inner.XDPEntryProg != "xdp_main_prog" {
		_ = m.inner.SwapXDPEntryProg("xdp_main_prog")
	}
	// Reset the ctrl enable gate so the fill-ring bootstrap delay
	// restarts from scratch after rebind.  Without this, ctrl stays
	// enabled while the new bindings aren't ready — packets redirected
	// to dead XSK sockets are silently dropped (cold-start blackout).
	//
	// Preserve ctrlEnableAt across rebinds: the hard timeout should
	// count from the FIRST prewarm, not restart on every link cycle.
	// Otherwise repeated rebinds (e.g. RETH MAC programming) keep
	// pushing the hard timeout forward and ctrl never enables.
	m.neighborsPrewarmed = false
	// Reset liveness state so the XSK probe runs fresh after rebind.
	// The old probe result is stale — the link cycle destroyed the
	// previous XSK sockets and the new ones need re-validation.
	m.xskLivenessProven = false
	m.xskLivenessFailed = false
	m.xskProbeStart = time.Time{}
	m.lastXSKRX = 0

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "rebind"}, &status); err != nil {
		slog.Warn("userspace: rebind after link cycle failed", "err", err)
		return
	}
	_ = m.applyHelperStatusLocked(&status)
	ready := 0
	for _, b := range status.Bindings {
		if b.Ready {
			ready++
		}
	}
	slog.Info("userspace: AF_XDP rebind initiated after link cycle",
		"forwarding_armed", status.ForwardingArmed,
		"bindings", len(status.Bindings),
		"ready", ready)
	// Re-bootstrap NAPI queues after rebind. The link DOWN/UP cycle
	// destroyed the XSK channels; the rebind created new sockets but
	// the fill ring WQEs haven't been posted to the NIC yet. Broadcast
	// pings generate hardware RX events that trigger NAPI, which posts
	// fill ring WQEs so zero-copy XSK can receive packets.
	m.bootstrapNAPIQueuesAsyncLocked("link-cycle")
}
