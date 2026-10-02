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
	"sync/atomic"
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
// cannot fire on frames that never arrive, so both sides run never-seen. If
// session sync is also silent, they promote via single-node election after the
// startup grace and claim PRIMARY with identical RETH MACs: the silent split-
// brain the README says is loudly logged.
//
// FIX. Each keyed heartbeat tenure sends a compact HMAC-authenticated identity
// beacon to the control-link subnet broadcast address on a dedicated UDP port.
// The beacon listener is bound to the heartbeat VRF and sees it even when
// unicast to the configured peer address cannot resolve. The receiver verifies
// the MAC and freshness BEFORE comparing node IDs or warning; an arbitrary L2
// sender or a forged UDP packet cannot produce the operator-facing ERROR.
// Beacons never update peer liveness, replay state, or election — they only
// surface the duplicate identity. The HMAC uses the same accepted control-link
// key set as heartbeats, so key rotation remains interoperable. A stable,
// authenticated per-process sender ID prevents a node from warning on its own
// locally looped-back broadcast, including beacons sent just before a
// heartbeat restart replaced the watcher.
//
// SCOPE. This is a small, authenticated day-0 identity signal, not another
// heartbeat transport: it carries only cluster/node identity and a fresh
// nonce, never peer state, and cannot make a peer appear alive. It runs only
// when the control-link PSK is configured (the documented HA shape); an
// unkeyed deployment has no way to authenticate a warning and keeps the
// existing heartbeat behavior. IPv4 directed broadcast is used because the
// shipped control link is IPv4; IPv6-only and /31-or-narrower control links
// cannot use the detector and emit a rate-limited setup warning. Freshness is
// a ±30s wall-clock window, so the pair must hold wall-clock within 30s
// (NTP/Chrony) or genuine duplicates are missed. Replay memory and the sender
// ID live on the manager: a watcher/heartbeat restart retains them, but a full
// process restart reopens a bounded capture-replay window, called out in the
// operator warning.

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
		return duplicateIdentityBroadcastForNetwork(local4, network)
	}
	return nil, fmt.Errorf("control-link address %s is not assigned to %s", local4, iface)
}

func duplicateIdentityBroadcastForNetwork(local4 net.IP, network *net.IPNet) (*net.UDPAddr, error) {
	prefix, bits := network.Mask.Size()
	ipv4 := local4.To4()
	if ipv4 == nil || bits != 32 || prefix >= 31 {
		return nil, fmt.Errorf("control-link address %s/%d has no IPv4 broadcast", local4, prefix)
	}
	broadcast := make(net.IP, net.IPv4len)
	for i := range broadcast {
		broadcast[i] = ipv4[i] | ^network.Mask[i]
	}
	return &net.UDPAddr{IP: broadcast, Port: duplicateIdentityBeaconPort}, nil
}

// duplicateIdentityReplayTTL retains a nonce until at least 30s after receipt,
// or until 30s after a future-skewed stamp's last freshness instant. The
// resulting deadline is formed from the receiver's local `now`, which has a
// monotonic component in production, so a forward wall-clock step cannot reap a
// nonce before its suppression interval ends. As with any finite in-memory
// cache, a rollback after expiry can restore freshness: at the maximum +30s
// future skew, the stamp is fresh at its 60s deadline and a 1s rollback just
// after expiry makes it fresh again.
func duplicateIdentityReplayTTL(stamp, now time.Time) time.Duration {
	ttl := duplicateIdentityBeaconMaxAge
	if stamp.After(now) {
		ttl += stamp.Sub(now)
	}
	return ttl
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

// duplicateIdentityReplayCap bounds the beacon nonce cache. Beacon sends are
// capped at 10/s regardless of heartbeat cadence (see sendInterval), and an
// accepted timestamp remains fresh for at most 60s from receipt under maximum
// future skew, so honest peer traffic holds at most ~600 live entries. At
// capacity, live entries are never evicted: new beacons are suppressed until
// an entry expires, preserving replay protection under a flood or clock skew.
const duplicateIdentityReplayCap = 4096

// duplicateIdentityReplayCache records observed beacon nonces with monotonic
// suppression deadlines derived from the signed wall-clock timestamp.
//
// It lives on the MANAGER (process lifetime), not on the watcher — the #5086
// precedent. A heartbeat restart replaces the watcher; a per-watcher cache
// would forget every nonce, so a keyless L2 observer could replay a captured
// still-fresh PEER beacon into the new tenure (valid MAC, still-foreign
// instance, nonce uncached) and manufacture a false duplicate warning after
// the peer is gone. A process restart necessarily recreates the in-memory
// cache; that residual is named in the operator warning because a still-fresh
// authenticated capture is indistinguishable from a live peer without durable
// replay state.
//
// Lock order is cache mu THEN m.mu (handleBeacon records here before the
// warning takes m.mu); no path takes them in the reverse order. The zero
// value is ready: the map is allocated lazily under the mutex, so Managers
// built as struct literals need no constructor change.
type duplicateIdentityReplayCache struct {
	mu      sync.Mutex
	entries map[[16]byte]time.Time // nonce -> monotonic suppression deadline
}

// checkAndRecord reports whether nonce was already recorded live, and whether
// capacity prevented recording a new nonce. deadline is the last instant the
// entry suppresses replays, inclusive. Expired entries are reclaimed before
// applying the cap, but a live entry is never evicted to admit a new nonce.
func (c *duplicateIdentityReplayCache) checkAndRecord(nonce [16]byte, deadline, now time.Time) (replay, full bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[[16]byte]time.Time)
	}
	if at, seen := c.entries[nonce]; seen && !now.After(at) {
		return true, false
	}
	if len(c.entries) >= duplicateIdentityReplayCap {
		for seen, at := range c.entries {
			if now.After(at) {
				delete(c.entries, seen)
			}
		}
		if len(c.entries) >= duplicateIdentityReplayCap {
			return false, true
		}
	}
	c.entries[nonce] = deadline
	return false, false
}

// sweep drops entries whose suppression deadline has passed. The deadline
// instant itself still suppresses (inclusive, matching freshness acceptance
// at exactly ±30s); only strictly-later sweeps reap. Called by the watcher's
// periodic sweep loop, so expiry never depends on further matching traffic.
func (c *duplicateIdentityReplayCache) sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for seen, at := range c.entries {
		if now.After(at) {
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
// m.mu: the key lookup below takes m.mu.RLock, and doing it inside that
// critical section would deadlock. Publication calls start only after its
// lifecycle epoch is rechecked. Socket setup is best-effort: failure to find
// an IPv4 broadcast or open a socket never prevents heartbeat startup, but it
// is operator-visible and rate-limited.
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
		reason := "no usable IPv4 broadcast address"
		if net.ParseIP(localAddr).To4() == nil {
			reason = "IPv6-only or non-IPv4 control link; duplicate-identity beacon signal is not supported"
		}
		mgr.noteDuplicateIdentityBeaconUnavailable(iface, reason, err)
		return nil
	}
	lc := vrfListenConfig(vrfDevice)
	listenPacket, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort("", fmt.Sprint(duplicateIdentityBeaconPort)))
	if err != nil {
		mgr.noteDuplicateIdentityBeaconUnavailable(iface, "IPv4 beacon listener unavailable", err)
		return nil
	}
	listen, ok := listenPacket.(*net.UDPConn)
	if !ok {
		listenPacket.Close()
		mgr.noteDuplicateIdentityBeaconUnavailable(iface, "beacon listener is not UDP", nil)
		return nil
	}
	sendPacket, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort(localAddr, "0"))
	if err != nil {
		listen.Close()
		mgr.noteDuplicateIdentityBeaconUnavailable(iface, "IPv4 beacon sender unavailable", err)
		return nil
	}
	send, ok := sendPacket.(*net.UDPConn)
	if !ok {
		listen.Close()
		sendPacket.Close()
		mgr.noteDuplicateIdentityBeaconUnavailable(iface, "beacon sender is not UDP", nil)
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
		mgr.noteDuplicateIdentityBeaconUnavailable(iface, "IPv4 broadcast socket setup failed", err)
		return nil
	}
	// The sender ID is the manager's stable per-process identity, not a fresh
	// random per watcher: a replacement watcher must still recognise this
	// node's own in-flight beacons (sent just before the restart) as self.
	return newDuplicateIdentityWatcher(mgr, iface, listen, send, broadcast, interval, mgr.beaconSenderID())
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

// duplicateIdentityBeaconMinSendInterval caps the beacon wire rate at 10/s
// regardless of heartbeat cadence. The schema allows 1ms heartbeat intervals
// and the watcher inherits that cadence; without this clamp an honest peer
// pair at 1ms would hold 1000/s x 60s = 60000 live nonces and overflow any
// sane cap with no attacker present. Day-0 duplicate detection needs no
// finer grain — 10/s still warns within a second — while the receive cache
// cap can then be sized for a bounded honest rate. The read deadline keeps
// the raw interval: only sends are decoupled.
const duplicateIdentityBeaconMinSendInterval = 100 * time.Millisecond

// sendInterval is the beacon transmit cadence: the heartbeat interval floored
// at the 10/s maximum rate.
func (w *duplicateIdentityWatcher) sendInterval() time.Duration {
	if w.interval < duplicateIdentityBeaconMinSendInterval {
		return duplicateIdentityBeaconMinSendInterval
	}
	return w.interval
}

func (w *duplicateIdentityWatcher) sendLoop() {
	defer w.wg.Done()
	w.sendBeacon()
	ticker := time.NewTicker(w.sendInterval())
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
		w.mgr.noteDuplicateIdentityBeaconSocketFailure(w.iface, "send", err)
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
// transient read errors are reported through the manager's 30s health-warning
// budget and continue (a transient failure must not silently kill day-0
// detection for the tenure), and only a closed stopCh ends the loop.
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
		w.mgr.noteDuplicateIdentityBeaconSocketFailure(w.iface, "read", err)
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
	deadline := now.Add(duplicateIdentityReplayTTL(stamp, now))
	replay, full := w.mgr.beaconReplay.checkAndRecord(nonce, deadline, now)
	if replay {
		return
	}
	if full {
		w.mgr.noteBeaconReplayCacheFull(w.iface)
		return
	}
	w.mgr.NoteDuplicateNodeIDBeacon(w.iface)
}

// noteDuplicateIdentityBeaconUnavailable keeps unsupported or failed
// best-effort setup visible without allowing heartbeat restarts to flood logs.
// It uses a separate budget from duplicate-node-id warnings.
func (m *Manager) noteDuplicateIdentityBeaconUnavailable(iface, reason string, err error) {
	m.noteBeaconHealthWarning(iface,
		"cluster: authenticated duplicate-identity beacon unavailable; the duplicate-node-id signal is not armed",
		reason, err)
}

// noteDuplicateIdentityBeaconSocketFailure reports runtime socket errors
// through the shared rate-limited health-warning budget. Read errors remain
// transient and do not stop the watcher.
func (m *Manager) noteDuplicateIdentityBeaconSocketFailure(iface, operation string, err error) {
	m.noteBeaconHealthWarning(iface,
		"cluster: authenticated duplicate-identity beacon socket failure; the signal may be degraded",
		operation, err)
}

// noteBeaconReplayCacheFull warns when bounded memory pressure suppresses new
// beacons. Existing live nonces are never evicted, so a cache flood cannot
// reopen their replay window.
func (m *Manager) noteBeaconReplayCacheFull(iface string) {
	m.noteBeaconHealthWarning(iface,
		"cluster: authenticated duplicate-identity beacon replay cache is full; new beacons are suppressed until entries expire",
		"", nil)
}

// noteBeaconHealthWarning shares a per-manager 30s budget among best-effort
// beacon health warnings. It does not consume the duplicate-node-id budget.
func (m *Manager) noteBeaconHealthWarning(iface, message, reason string, err error) {
	m.mu.Lock()
	now := time.Now()
	if !m.lastBeaconHealthWarn.IsZero() && now.Sub(m.lastBeaconHealthWarn) < 30*time.Second {
		m.mu.Unlock()
		return
	}
	m.lastBeaconHealthWarn = now
	m.mu.Unlock()
	if err != nil {
		slog.Warn(message, "iface", iface, "reason", reason, "err", err)
		return
	}
	if reason != "" {
		slog.Warn(message, "iface", iface, "reason", reason)
		return
	}
	slog.Warn(message, "iface", iface)
}

// NoteDuplicateNodeIDBeacon records an authenticated broadcast beacon carrying
// this node's own identity. The in-memory replay cache survives heartbeat
// tenure replacement, but is lost on process restart: a captured still-fresh
// frame can therefore produce the same warning as a live peer. Keep that
// uncertainty and the recovery action explicit. The shared warning budget
// limits this signal to one event per 30s.
func (m *Manager) NoteDuplicateNodeIDBeacon(iface string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.duplicateNodeIDWarningDueLocked() {
		return
	}
	slog.Error("cluster: duplicate node-id detected — received an authenticated "+
		"control-link identity beacon carrying this node's own node-id; this is an "+
		"INVALID cluster configuration (two chassis cannot share a node-id). The "+
		"beacon is only a warning and does not prove current peer liveness or drive "+
		"election, so each eligible RG can promote via single-node election once "+
		"the startup peer-absent grace elapses; if both nodes are eligible, both "+
		"claim PRIMARY with duplicate VIPs on the segment. The nonce cache is "+
		"process-scoped, so a still-fresh captured beacon may also trigger this "+
		"warning after a process restart. If both chassis are present, correct "+
		"/etc/xpf/node-id on one node. Verify the peer on the control link; if "+
		"unexpected, rotate the control-link PSK on both nodes.",
		"iface", iface, "node_id", m.nodeID)
	if m.history != nil {
		m.history.Record(EventRG, -1, "duplicate node-id: authenticated control-link beacon")
	}
}

// beaconSenderIDFallback distinguishes fallback sender IDs when crypto/rand
// is unavailable (essentially never on Linux; getrandom failure).
var beaconSenderIDFallback atomic.Uint64

// beaconSenderID returns this node's stable beacon sender ID, minting it on
// first use. Every watcher preparation takes the same ID, so a replacement
// watcher recognises this node's own in-flight beacons as self rather than
// as a foreign duplicate. Safe for struct-literal Managers. Takes m.mu —
// callers must not hold it (prepare runs pre-lock for exactly this reason).
func (m *Manager) beaconSenderID() [16]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.beaconSenderIDSet {
		return m.beaconSenderIDValue
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		// Uniqueness here only needs self-consistency within this process:
		// nanotime plus a process-wide counter cannot collide with a live
		// peer's random ID except by chance, and the consequence of even
		// that is one missed warn on a warn-only path.
		binary.LittleEndian.PutUint64(id[:8], uint64(time.Now().UnixNano()))
		binary.LittleEndian.PutUint64(id[8:], beaconSenderIDFallback.Add(1))
	}
	m.beaconSenderIDValue = id
	m.beaconSenderIDSet = true
	return id
}
