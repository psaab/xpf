package cluster

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// #10745: an authenticated control-link identity beacon.
//
// WHY THE HEARTBEAT PATH CANNOT FIRE HERE. In the documented shared `${node}`
// shape (examples/deploy/ha-pair.conf), the selected em0 address AND the
// peer-address live inside the same node0/node1 groups. Two chassis with the
// same node-id therefore hold the SAME em0 address (.1) and the SAME
// peer-address (.2) — an address NOBODY holds. Each node's kernel ARPs for
// the unheld peer address forever, the ARP is never answered, and no
// heartbeat datagram is ever delivered. Any receive-path UDP detector —
// including the #4549 F11 same-node-id check behind the #6888 peer pin —
// cannot fire on frames that never arrive, so both sides run never-seen,
// promote via single-node election after the startup grace, and claim
// PRIMARY with identical RETH MACs: the silent split-brain the README says
// is loudly logged.
//
// FIX. Each keyed heartbeat tenure sends a compact HMAC-authenticated identity
// beacon to the control-link subnet broadcast address on a dedicated UDP port.
// The beacon listener is bound to the heartbeat VRF and sees it even when
// unicast to the configured peer address cannot resolve. The receiver verifies
// the MAC and freshness BEFORE comparing node IDs or warning; an arbitrary L2
// sender or a forged UDP packet cannot produce the operator-facing ERROR.
// Beacons never update peer liveness, replay state, or election — they only
// surface the duplicate identity. The HMAC uses the same accepted control-link
// key set as heartbeats, so key rotation remains interoperable. A random,
// authenticated per-process sender ID prevents a node from warning on its own
// locally looped-back broadcast.
//
// SCOPE. This is a small, authenticated day-0 identity signal, not another
// heartbeat transport: it carries only cluster/node identity and a fresh
// nonce, never peer state, and cannot make a peer appear alive. It runs only
// when the control-link PSK is configured (the documented HA shape); an
// unkeyed deployment has no way to authenticate a warning and keeps the
// existing heartbeat behavior. IPv4 directed broadcast is used because the
// shipped control link is IPv4; IPv6-only control links skip this detector.
// Freshness is a ±30s wall-clock window, so the pair must hold wall-clock
// within 30s (NTP/Chrony) or genuine duplicates are missed. Replay memory is
// process-lifetime (manager cache), so only a full process restart reopens a
// bounded capture-replay window — never a heartbeat restart.

const (
	duplicateIdentityBeaconPort    = 4786
	duplicateIdentityBeaconMagic   = "XPFID001"
	duplicateIdentityBeaconTag     = "xpf cluster duplicate identity beacon v1"
	duplicateIdentityBeaconLen     = 8 + 2 + 1 + 8 + 16 + 16 + sha256.Size
	duplicateIdentityBeaconMaxAge  = 30 * time.Second
	duplicateIdentityBeaconReadLen = 128
)

// duplicateIdentityBroadcastAddr derives the IPv4 subnet broadcast for a local
// address assigned to iface. Prefix lengths /31 and /32 have no host broadcast
// and cannot carry this detector's beacon.
func duplicateIdentityBroadcastAddr(iface string, localIP net.IP) (*net.UDPAddr, error) {
	local4 := localIP.To4()
	if local4 == nil {
		return nil, fmt.Errorf("control-link address %s is not IPv4", localIP)
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("control interface %s: %w", iface, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, fmt.Errorf("addresses for control interface %s: %w", iface, err)
	}
	for _, addr := range addrs {
		ip, network, err := net.ParseCIDR(addr.String())
		if err != nil || ip.To4() == nil || !ip.To4().Equal(local4) {
			continue
		}
		prefix, bits := network.Mask.Size()
		if bits != 32 || prefix >= 31 {
			return nil, fmt.Errorf("control-link address %s/%d has no IPv4 broadcast", local4, prefix)
		}
		broadcast := make(net.IP, net.IPv4len)
		for i := range broadcast {
			broadcast[i] = ip.To4()[i] | ^network.Mask[i]
		}
		return &net.UDPAddr{IP: broadcast, Port: duplicateIdentityBeaconPort}, nil
	}
	return nil, fmt.Errorf("control-link address %s is not assigned to %s", local4, iface)
}

// marshalDuplicateIdentityBeacon signs a short, fresh statement of the local
// cluster and node identity. HMAC covers the timestamp, random sender-instance
// ID and nonce as well as identity, so receivers can reject forgery and stale
// replays before warning. Key bytes are never rendered or persisted.
func marshalDuplicateIdentityBeacon(clusterID, nodeID int, key []byte, instanceID [16]byte, now time.Time) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("control-link authentication key is not configured")
	}
	if clusterID < 0 || clusterID > 0xffff || nodeID < 0 || nodeID > 0xff {
		return nil, fmt.Errorf("identity out of beacon range: cluster=%d node=%d", clusterID, nodeID)
	}
	frame := make([]byte, duplicateIdentityBeaconLen)
	copy(frame[:8], duplicateIdentityBeaconMagic)
	binary.LittleEndian.PutUint16(frame[8:10], uint16(clusterID))
	frame[10] = byte(nodeID)
	binary.LittleEndian.PutUint64(frame[11:19], uint64(now.UnixNano()))
	copy(frame[19:35], instanceID[:])
	if _, err := rand.Read(frame[35:51]); err != nil {
		return nil, fmt.Errorf("create duplicate-identity beacon nonce: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(duplicateIdentityBeaconTag))
	_, _ = mac.Write(frame[:51])
	copy(frame[51:], mac.Sum(nil))
	return frame, nil
}

// verifyDuplicateIdentityBeacon authenticates and freshness-checks a beacon
// using every currently accepted PSK. It returns identity, sender instance,
// nonce and the signed timestamp, but ONLY after all checks pass; callers
// MUST NOT warn based on the unsigned header.
func verifyDuplicateIdentityBeacon(frame []byte, mgr *Manager, now time.Time) (clusterID, nodeID int, instanceID, nonce [16]byte, stamp time.Time, ok bool) {
	if mgr == nil || len(frame) != duplicateIdentityBeaconLen ||
		string(frame[:8]) != duplicateIdentityBeaconMagic {
		return 0, 0, instanceID, nonce, stamp, false
	}
	stamp = time.Unix(0, int64(binary.LittleEndian.Uint64(frame[11:19])))
	delta := now.Sub(stamp)
	if delta < -duplicateIdentityBeaconMaxAge || delta > duplicateIdentityBeaconMaxAge {
		return 0, 0, instanceID, nonce, time.Time{}, false
	}
	keys := mgr.controlLinkAcceptedKeys()
	if len(keys) == 0 {
		return 0, 0, instanceID, nonce, time.Time{}, false
	}
	validMAC := false
	for _, key := range keys {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(duplicateIdentityBeaconTag))
		_, _ = mac.Write(frame[:51])
		if hmac.Equal(frame[51:], mac.Sum(nil)) {
			validMAC = true
			break
		}
	}
	if !validMAC {
		return 0, 0, instanceID, nonce, time.Time{}, false
	}
	copy(instanceID[:], frame[19:35])
	copy(nonce[:], frame[35:51])
	return int(binary.LittleEndian.Uint16(frame[8:10])), int(frame[10]), instanceID, nonce, stamp, true
}

// duplicateIdentityReplayCap bounds the beacon nonce cache. A genuine
// duplicate peer emits ~10 beacons/s, so ~300 entries cover the 30s window
// with clock skew; 4096 is a decade of headroom that keeps worst-case memory
// under half a megabyte while a PSK-holder flood cannot grow it further.
const duplicateIdentityReplayCap = 4096

// duplicateIdentityReplayCache records observed beacon nonces with the
// instant each entry stops suppressing replays.
//
// It lives on the MANAGER (process lifetime), not on the watcher — the #5086
// precedent. A heartbeat restart replaces the watcher; a per-watcher cache
// would forget every nonce, so a keyless L2 observer could replay a captured
// still-fresh beacon into the new tenure (valid MAC, old instance now
// foreign, nonce uncached) and manufacture a false duplicate warning. A
// tenure ID inside the MAC cannot fix that — the receiver cannot know the
// peer's current tenure — but replay memory that survives watcher
// replacement can: the replayed nonce is already recorded.
//
// Lock order is cache mu THEN m.mu (handleBeacon records here before the
// warning takes m.mu); no path takes them in the reverse order. The zero
// value is ready: the map is allocated lazily under the mutex, so Managers
// built as struct literals need no constructor change.
type duplicateIdentityReplayCache struct {
	mu      sync.Mutex
	entries map[[16]byte]time.Time // nonce -> suppression deadline
}

// checkAndRecord reports whether nonce was already recorded live, and records
// it when it was not. deadline is when the entry stops suppressing replays
// (BEACON-02: max(receipt, stamp)+MaxAge, so a skewed-future beacon's nonce
// always outlives its timestamp's validity). At capacity, expired entries go
// first and one arbitrary survivor is evicted only when nothing had expired —
// memory stays bounded under a PSK-holder flood.
func (c *duplicateIdentityReplayCache) checkAndRecord(nonce [16]byte, deadline time.Time, now time.Time) (replay bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[[16]byte]time.Time)
	}
	if at, seen := c.entries[nonce]; seen && now.Before(at) {
		return true
	}
	if len(c.entries) >= duplicateIdentityReplayCap {
		for seen, at := range c.entries {
			if !now.Before(at) {
				delete(c.entries, seen)
			}
		}
		if len(c.entries) >= duplicateIdentityReplayCap {
			for seen := range c.entries {
				delete(c.entries, seen)
				break // Go map order is random: evict-random on overflow
			}
		}
	}
	c.entries[nonce] = deadline
	return false
}

// sweep drops entries whose suppression deadline has passed. Called by the
// watcher's periodic sweep loop, so expiry never depends on further matching
// traffic arriving.
func (c *duplicateIdentityReplayCache) sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for seen, at := range c.entries {
		if !now.Before(at) {
			delete(c.entries, seen)
		}
	}
}

// len reports the entry count for tests.
func (c *duplicateIdentityReplayCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// duplicateIdentityWatcher owns the authenticated broadcast sender and
// receiver for one heartbeat tenure.
type duplicateIdentityWatcher struct {
	mgr       *Manager
	iface     string
	listen    *net.UDPConn
	send      *net.UDPConn
	broadcast *net.UDPAddr
	interval  time.Duration
	stopCh    chan struct{}
	wg        sync.WaitGroup
	instance  [16]byte
	sendErr   sync.Once
}

func newDuplicateIdentityWatcher(mgr *Manager, iface string, listen, send *net.UDPConn, broadcast *net.UDPAddr, interval time.Duration, instance [16]byte) *duplicateIdentityWatcher {
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}
	return &duplicateIdentityWatcher{
		mgr: mgr, iface: iface, listen: listen, send: send, broadcast: broadcast,
		interval: interval, stopCh: make(chan struct{}), instance: instance,
	}
}

// prepareDuplicateIdentityWatcher creates the keyed L2 identity detector's
// sockets without starting goroutines. It runs before startHeartbeat acquires
// m.mu for publication: the key lookup below takes m.mu.RLock, and doing it
// inside that critical section would deadlock. Publication calls start only
// after its lifecycle epoch is rechecked. Socket setup is best-effort: failure
// to find an IPv4 broadcast or open a socket never prevents heartbeat startup.
func prepareDuplicateIdentityWatcher(mgr *Manager, iface, localAddr, vrfDevice string, interval time.Duration) *duplicateIdentityWatcher {
	if mgr == nil || iface == "" {
		return nil
	}
	if len(mgr.controlLinkAuthKey()) == 0 {
		slog.Debug("cluster: authenticated duplicate-identity watcher skipped without control-link key",
			"iface", iface)
		return nil
	}
	broadcast, err := duplicateIdentityBroadcastAddr(iface, net.ParseIP(localAddr))
	if err != nil {
		slog.Debug("cluster: authenticated duplicate-identity watcher skipped",
			"iface", iface, "err", err)
		return nil
	}
	lc := vrfListenConfig(vrfDevice)
	listenPacket, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort("", fmt.Sprint(duplicateIdentityBeaconPort)))
	if err != nil {
		slog.Debug("cluster: authenticated duplicate-identity listener unavailable",
			"iface", iface, "err", err)
		return nil
	}
	listen, ok := listenPacket.(*net.UDPConn)
	if !ok {
		listenPacket.Close()
		slog.Debug("cluster: authenticated duplicate-identity listener is not UDP", "iface", iface)
		return nil
	}
	sendPacket, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort(localAddr, "0"))
	if err != nil {
		listen.Close()
		slog.Debug("cluster: authenticated duplicate-identity sender unavailable",
			"iface", iface, "err", err)
		return nil
	}
	send, ok := sendPacket.(*net.UDPConn)
	if !ok {
		listen.Close()
		sendPacket.Close()
		slog.Debug("cluster: authenticated duplicate-identity sender is not UDP", "iface", iface)
		return nil
	}
	raw, err := send.SyscallConn()
	if err == nil {
		var socketErr error
		err = raw.Control(func(fd uintptr) {
			socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
		})
		if err == nil {
			err = socketErr
		}
	}
	if err != nil {
		listen.Close()
		send.Close()
		slog.Debug("cluster: authenticated duplicate-identity broadcast unavailable",
			"iface", iface, "err", err)
		return nil
	}
	var instance [16]byte
	if _, err := rand.Read(instance[:]); err != nil {
		listen.Close()
		send.Close()
		slog.Debug("cluster: authenticated duplicate-identity instance ID unavailable",
			"iface", iface, "err", err)
		return nil
	}
	return newDuplicateIdentityWatcher(mgr, iface, listen, send, broadcast, interval, instance)
}

// duplicateIdentityReplaySweepInterval paces the watcher's replay-cache sweep
// loop. Entries live at most MaxAge past the later of receipt and stamp (60s
// worst case under full future skew), so a 5s sweep keeps dead entries' memory
// negligible without per-packet prune work.
const duplicateIdentityReplaySweepInterval = 5 * time.Second

// start launches every loop after a watcher has been published in Manager.
func (w *duplicateIdentityWatcher) start() {
	if w.listen != nil {
		w.wg.Add(1)
		go w.readLoop()
	}
	if w.send != nil && w.broadcast != nil {
		w.wg.Add(1)
		go w.sendLoop()
	}
	w.wg.Add(1)
	go w.sweepLoop()
	slog.Debug("cluster: authenticated duplicate-identity watcher started",
		"iface", w.iface, "broadcast", w.broadcast)
}

// sweepLoop expires replay-cache entries on a timer, so dead entries are
// reclaimed even when no further beacons arrive (traffic-independent expiry).
func (w *duplicateIdentityWatcher) sweepLoop() {
	defer w.wg.Done()
	ticker := time.NewTicker(duplicateIdentityReplaySweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case now := <-ticker.C:
			w.mgr.beaconReplay.sweep(now)
		}
	}
}

// stop tears down both sockets before joining, unblocking a read parked in the
// kernel. stopHeartbeat transfers this handle to exactly one caller.
func (w *duplicateIdentityWatcher) stop() {
	close(w.stopCh)
	if w.listen != nil {
		_ = w.listen.Close()
	}
	if w.send != nil {
		_ = w.send.Close()
	}
	w.wg.Wait()
}

func (w *duplicateIdentityWatcher) sendLoop() {
	defer w.wg.Done()
	w.sendBeacon()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.sendBeacon()
		}
	}
}

func (w *duplicateIdentityWatcher) sendBeacon() {
	frame, err := marshalDuplicateIdentityBeacon(w.mgr.ClusterID(), w.mgr.NodeID(),
		w.mgr.controlLinkAuthKey(), w.instance, time.Now())
	if err == nil {
		_, err = w.send.WriteToUDP(frame, w.broadcast)
	}
	if err != nil {
		w.sendErr.Do(func() {
			slog.Debug("cluster: authenticated duplicate-identity beacon send failed",
				"iface", w.iface, "err", err)
		})
	}
}

func (w *duplicateIdentityWatcher) readLoop() {
	defer w.wg.Done()
	buf := make([]byte, duplicateIdentityBeaconReadLen)
	for {
		n, alive := w.readStep(buf)
		if !alive {
			return
		}
		if n > 0 {
			w.handleBeacon(buf[:n], time.Now())
		}
	}
}

// readStep performs one socket read and reports whether the loop stays alive.
// The error policy is heartbeatReceiver.readLoop's, exactly: timeouts and
// transient read errors continue (a transient failure must not silently kill
// day-0 detection for the tenure), and only a closed stopCh ends the loop.
// The stopCh pre-check is the sibling's loop-top select inlined: without it a
// stopped watcher whose socket only ever times out would spin instead of
// exiting. Split out so the continue-vs-return policy is unit-testable
// without driving the goroutine.
func (w *duplicateIdentityWatcher) readStep(buf []byte) (int, bool) {
	select {
	case <-w.stopCh:
		return 0, false
	default:
	}
	_ = w.listen.SetReadDeadline(time.Now().Add(w.interval))
	n, _, err := w.listen.ReadFromUDP(buf)
	if err == nil {
		return n, true
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return 0, true
	}
	select {
	case <-w.stopCh:
		return 0, false
	default:
		slog.Debug("cluster: authenticated duplicate-identity read error",
			"iface", w.iface, "err", err)
		return 0, true
	}
}

// handleBeacon authenticates before any duplicate-identity decision or warning.
// Sender-instance IDs exclude the local socket's own broadcast loopback; the
// manager-lifetime nonce cache suppresses exact packet replays, including
// replays delivered after this watcher replaced an older one.
func (w *duplicateIdentityWatcher) handleBeacon(frame []byte, now time.Time) {
	clusterID, nodeID, instance, nonce, stamp, ok := verifyDuplicateIdentityBeacon(frame, w.mgr, now)
	if !ok || clusterID != w.mgr.ClusterID() || nodeID != w.mgr.NodeID() || instance == w.instance {
		return
	}
	deadline := now
	if stamp.After(deadline) {
		deadline = stamp
	}
	if w.mgr.beaconReplay.checkAndRecord(nonce, deadline.Add(duplicateIdentityBeaconMaxAge), now) {
		return
	}
	w.mgr.NoteDuplicateNodeIDBeacon(w.iface)
}

// NoteDuplicateNodeIDBeacon records an authenticated broadcast beacon carrying
// this node's own identity. In the shared `${node}` shape both chassis hold the
// same local address and the unicast peer address is held by neither; signed
// directed-broadcast beacons are the only live peer signal that can cross that
// gap. Authentication is checked before this method is reached. The beacon is
// not a heartbeat: the peer remains absent and each eligible RG can promote via
// single-node election on both nodes, so the warning names that outcome. Takes
// m.mu.
func (m *Manager) NoteDuplicateNodeIDBeacon(iface string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.duplicateNodeIDWarningDueLocked() {
		return
	}
	slog.Error("cluster: duplicate node-id detected — received an authenticated "+
		"control-link identity beacon carrying this node's own node-id; this is an "+
		"INVALID cluster configuration (two chassis cannot share a node-id). The "+
		"beacon is only a warning and does not refresh peer liveness or drive "+
		"election, so each eligible RG can promote via single-node election once "+
		"the startup peer-absent grace elapses; if both nodes are eligible, both "+
		"claim PRIMARY with duplicate VIPs on the segment. Correct /etc/xpf/node-id "+
		"on one node.",
		"iface", iface, "node_id", m.nodeID)
	if m.history != nil {
		m.history.Record(EventRG, -1, "duplicate node-id: authenticated control-link beacon")
	}
}
