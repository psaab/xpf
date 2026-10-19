package vrrp

import (
	"log/slog"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
)

// Interface tracking (#1814). Single-interface tracking per VRRP group
// lowers the advertised priority while the tracked link is down so a
// healthy peer can take over. This file owns both the per-instance
// effective-priority primitives and the manager-side singleton
// link-watcher / poller that feeds link state into tracking instances.

// getPriority returns the effective advertised priority (#1814).
//   - cfg.Priority 0 is the resignation sentinel (ResignRG / shutdown
//     burst) and passes through UNCHANGED — the tracking clamp must
//     never apply to it.
//   - cfg.Priority 255 is the IP address owner: tracking is ignored
//     (an owner stepping down while still holding the address invites
//     duplicate-IP conflicts; the compiler warns at commit).
//   - Otherwise, while the tracked interface is down, TrackPriorityCost
//     is subtracted and the result clamped to [1, 254] so tracking can
//     never fabricate the priority-0 resignation sentinel.
//
// The no-track path returns cfg.Priority unchanged. Called from the
// advert path and masterDownInterval computation — keep it lock-cheap.
func (vi *vrrpInstance) getPriority() int {
	// A pending forced resignation (#15213 A25-06) must not leak
	// priority 0 into the routine MASTER advert path: ResignRG stashes
	// 0 in resignPriority while cfg.Priority still carries the
	// pre-resign value, and the run loop's advertTimer arm sends
	// getPriority(). Until becomeBackup consumes the resignation, a
	// routine advert therefore still carries the pre-resign priority;
	// only the explicit post-becomeBackup burst sends 0.
	vi.resignMu.Lock()
	pending := vi.resignPending
	vi.resignMu.Unlock()
	if pending {
		vi.mu.RLock()
		p := vi.cfg.Priority
		trackDown := vi.trackDown && vi.cfg.TrackInterface != ""
		cost := vi.cfg.TrackPriorityCost
		vi.mu.RUnlock()
		if p == 0 || p == addressOwnerPriority {
			return p
		}
		if trackDown {
			p -= cost
			if p < 1 {
				p = 1
			} else if p > 254 {
				p = 254
			}
		}
		return p
	}
	_, effective, _ := vi.prioritySnapshot()
	return effective
}

// prioritySnapshot returns the configured priority, the effective
// (track-demoted) priority getPriority would advertise, and whether
// tracking is currently demoting this instance. getPriority delegates
// here so status surfaces and the advert path can never disagree
// about the tracked value (#15213 A25-04).
func (vi *vrrpInstance) prioritySnapshot() (configured, effective int, trackDown bool) {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	configured = vi.cfg.Priority
	effective = configured
	if effective == 0 || effective == addressOwnerPriority {
		return configured, effective, false
	}
	if vi.trackDown && vi.cfg.TrackInterface != "" {
		effective -= vi.cfg.TrackPriorityCost
		if effective < 1 {
			effective = 1
		} else if effective > 254 {
			effective = 254
		}
		return configured, effective, true
	}
	return configured, effective, false
}

// setTrackDown records the tracked interface's link state. Logs only on
// transition — never per-event.
//
// The state machine needs no kick. A MASTER keeps advertising at the
// new (lower) effective priority via getPriority(); a preempt-enabled
// backup hearing that LOWER advert IGNORES it and lets its masterDown
// timer expire (handleBackupRx tail — instance.go:737 at plan time:
// "If preempt is true and incoming priority < ours, ignore — let timer
// expire"). So takeover after a tracked-link demotion lands in
// ~masterDownInterval (3×advert+skew: ≈97ms at 30ms adverts, ≈3.3s at
// 1s adverts) — RFC 5798 behavior, no forced abdication.
func (vi *vrrpInstance) setTrackDown(down bool) {
	vi.mu.Lock()
	changed := vi.trackDown != down
	vi.trackDown = down
	trackIface := vi.cfg.TrackInterface
	vi.mu.Unlock()
	if changed && trackIface != "" {
		slog.Info("vrrp: tracked interface state change",
			"key", vi.key(), "track_interface", trackIface,
			"down", down, "effective_priority", vi.getPriority())
	}
}

// trackedInterface returns the tracked Linux interface name, or "" when
// tracking is not configured.
func (vi *vrrpInstance) trackedInterface() string {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.cfg.TrackInterface
}

// ensureLinkWatcherLocked starts the singleton link-watcher goroutine.
// Caller MUST hold m.mu: watcherRunning latches under the manager mutex
// so UpdateInstances churn can never spawn a second watcher (#1814).
func (m *Manager) ensureLinkWatcherLocked() {
	if m.watcherRunning {
		return
	}
	m.watcherRunning = true
	m.watcherStarts++
	// Capture the current run-generation stop channel and hand it to the
	// goroutine. A Stop()->Start() cycle re-allocates m.watcherStop
	// (resetRunStateLocked, #2625); pinning the channel here means this
	// watcher always cancels on, and clears the latch against, its OWN
	// generation — a lingering pre-Stop watcher can never read the new
	// generation's channel nor clobber the new watcher's latch.
	stop := m.watcherStop
	go m.runLinkWatcher(stop)
}

// clearLinkWatcherLatch resets the singleton link-watcher latch so a future
// UpdateInstances can re-start the watcher after the watcher goroutine
// returns (Stop()-driven cancellation, or the poller fallback exiting).
// Mirrors clearAddrWatcherLatch (#2528). Resetting on exit keeps the latch
// honest: a watcher that has returned is not "running", so a later
// ensureLinkWatcherLocked must be free to spawn a fresh one (#2625).
//
// The stop arg is the generation token: the latch is cleared ONLY if it still
// belongs to this watcher's generation (m.watcherStop unchanged since spawn).
// After a Stop()->Start() the channel is re-allocated and a fresh watcher may
// already be latched — a lingering old watcher must NOT reset that newer
// latch. Stop() itself clears the latch on the next Start() via
// resetRunStateLocked, so this is the in-process belt-and-suspenders.
func (m *Manager) clearLinkWatcherLatch(stop chan struct{}) {
	m.mu.Lock()
	if m.watcherStop == stop {
		m.watcherRunning = false
	}
	m.mu.Unlock()
}

// runLinkWatcher is the singleton tracked-link watcher (#1814). It
// subscribes to netlink link updates and pushes trackDown into every
// instance tracking the affected interface. The tracked-ifname →
// instance mapping is re-read from the manager under lock on EVERY
// event — instance churn is never captured stale. Each event is fed
// through applyLinkEvent, which keys on the stable ifindex so a runtime
// kernel rename (a single RTM_NEWLINK with the same ifindex but a new
// name) demotes an instance tracking the now-vanished old name (#2944).
// Cancellation follows
// the done-channel pattern (pkg/daemon/daemon_flow.go): m.watcherStop
// is closed from Manager.Stop and the netlink subscription observes the
// same channel. On subscribe failure (or unexpected subscription close)
// it degrades to a 1 s poll that runs only while tracked instances
// exist.
func (m *Manager) runLinkWatcher(stop chan struct{}) {
	// Clear the singleton latch on ANY exit (Stop() cancellation, or the
	// poller fallback returning) so a later UpdateInstances can re-spawn the
	// watcher on a reused Manager (#2625). runLinkPoller is called
	// synchronously (a tail-call within this goroutine, not a new go), so a
	// single defer here covers every exit path including the poller's.
	defer m.clearLinkWatcherLatch(stop)
	ch := make(chan netlink.LinkUpdate, 64)
	if err := m.subscribeLinks(ch, stop); err != nil {
		slog.Warn("vrrp: link subscribe failed, falling back to 1s link polling", "err", err)
		m.runLinkPoller(stop)
		return
	}
	slog.Info("vrrp: link watcher started (interface tracking)")
	for {
		select {
		case <-stop:
			return
		case u, ok := <-ch:
			if !ok {
				select {
				case <-stop:
					return
				default:
				}
				slog.Warn("vrrp: link subscription closed, falling back to 1s link polling")
				m.runLinkPoller(stop)
				return
			}
			attrs := u.Attrs()
			if attrs == nil {
				continue
			}
			del := u.Header.Type == unix.RTM_DELLINK
			up := !del && linkAttrsUp(attrs)
			m.applyLinkEvent(attrs.Index, attrs.Name, del, up)
		}
	}
}

// runLinkPoller is the subscribe-failure fallback: poll tracked link
// state at 1 s. pollTrackedLinks performs no netlink queries while no
// instance tracks an interface. stop is the watcher's pinned run-generation
// cancellation channel (#2625).
func (m *Manager) runLinkPoller(stop chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			m.pollTrackedLinks()
		}
	}
}

// pollTrackedLinks queries link state once for each distinct tracked
// interface and applies it to the tracking instances.
func (m *Manager) pollTrackedLinks() {
	m.mu.RLock()
	tracked := make(map[string][]*vrrpInstance)
	for _, vi := range m.instances {
		if name := vi.trackedInterface(); name != "" {
			tracked[name] = append(tracked[name], vi)
		}
	}
	m.mu.RUnlock()
	for name, vis := range tracked {
		up, err := m.linkState(name)
		down := err != nil || !up
		for _, vi := range vis {
			vi.setTrackDown(down)
		}
	}
}

// applyLinkEvent feeds a single netlink link event into interface tracking,
// robust to a runtime kernel rename (#2944).
//
// The kernel emits a rename (e.g. wan0 -> wan1) as a SINGLE RTM_NEWLINK that
// carries the SAME ifindex with the NEW name and NO RTM_DELLINK for the old
// name. The pre-#2944 watcher applied state strictly by the event's name, so
// an instance tracking the old name never saw the event and kept its last
// (typically up) trackDown forever — it never demoted even though the
// configured interface no longer existed.
//
// We key rename detection on the stable ifindex via the m.linkNames cache:
//   - The event's own up/down is authoritative for instances tracking the
//     event's CURRENT name (the normal up/down/delete path, no extra syscall).
//   - When this ifindex previously carried a DIFFERENT name, that old name has
//     been renamed away. We re-evaluate it against the kernel (linkState):
//     LinkByName fails for a name that no longer exists, so the instance
//     tracking it demotes. This matches Junos semantics — tracking follows the
//     configured NAME, and a name that has been renamed away is treated as
//     down (it does NOT silently follow the ifindex to the new name).
//
// The cache is seeded at watcher start by the ListExisting subscribe
// (netlinkLinkSubscribe), so an interface that has been up since boot — and
// thus produced no prior event — is already known when its first runtime event
// (the rename) arrives.
func (m *Manager) applyLinkEvent(ifindex int, name string, del, up bool) {
	m.mu.Lock()
	prev, hadPrev := m.linkNames[ifindex]
	if del {
		delete(m.linkNames, ifindex)
	} else {
		m.linkNames[ifindex] = name
	}
	m.mu.Unlock()

	// Apply the event's operational state to instances tracking the event's
	// name. A delete is unconditionally down regardless of the carried attrs.
	if name != "" {
		m.applyTrackedLinkState(name, up && !del)
	}

	// Rename / replacement detection: this ifindex used to carry a different
	// name, which is now gone from it. Settle that old name against current
	// kernel state so an instance tracking the renamed-away name demotes.
	if hadPrev && prev != "" && prev != name {
		m.reevaluateTrackedName(prev)
	}
}

// reevaluateTrackedName queries current kernel state for a single interface
// name and applies it to every instance tracking that name (#2944). Used to
// settle the OLD name after a rename: linkState (LinkByName) returns an error
// for a name that no longer resolves to any link, which counts as down — the
// same convention pollTrackedLinks uses.
func (m *Manager) reevaluateTrackedName(name string) {
	up, err := m.linkState(name)
	m.applyTrackedLinkState(name, err == nil && up)
}

// applyTrackedLinkState updates trackDown on every instance tracking
// ifName. Takes only the manager read lock; setTrackDown takes the
// per-instance lock (no reverse ordering exists — instances never take
// m.mu).
func (m *Manager) applyTrackedLinkState(ifName string, up bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, vi := range m.instances {
		if vi.trackedInterface() == ifName {
			vi.setTrackDown(!up)
		}
	}
}

// seedTrackState initializes an instance's trackDown from current
// kernel link state at instance create/update time (the netlink
// subscription only streams future updates). A missing tracked
// interface counts as down.
func (m *Manager) seedTrackState(vi *vrrpInstance, trackIface string) {
	if trackIface == "" {
		vi.setTrackDown(false)
		return
	}
	up, err := m.linkState(trackIface)
	if err != nil {
		slog.Warn("vrrp: tracked interface lookup failed, treating as down",
			"key", vi.key(), "track_interface", trackIface, "err", err)
		vi.setTrackDown(true)
		return
	}
	vi.setTrackDown(!up)
}

// netlinkLinkSubscribe is the production subscribeLinks seam. It subscribes to
// netlink link updates with ListExisting=true so the kernel replays every
// current link as an RTM_NEWLINK immediately after subscribe. This seeds the
// watcher's ifindex->name cache (m.linkNames) from current state, so a
// runtime rename of an interface that has been up since boot — and thus
// produced no prior event — is still detected on its first event (#2944).
// ListExisting only front-loads current state; the watcher's event handling is
// idempotent, so the replay sets each tracked interface to its current up/down
// (consistent with seedTrackState) and matches nothing for untracked names.
func netlinkLinkSubscribe(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
	return netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ListExisting: true,
	})
}

// netlinkLinkState is the production linkState seam: report whether the
// named link is operationally up.
func netlinkLinkState(name string) (bool, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return false, err
	}
	return linkAttrsUp(link.Attrs()), nil
}

// linkAttrsUp interprets link operational state. OperUnknown is common
// on virtual devices that report no carrier state — fall back to the
// IFF_UP admin flag there.
func linkAttrsUp(attrs *netlink.LinkAttrs) bool {
	switch attrs.OperState {
	case netlink.OperUp:
		return true
	case netlink.OperUnknown:
		return attrs.Flags&net.FlagUp != 0
	default:
		return false
	}
}
