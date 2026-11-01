// Package fabricsegment watches a chassis-cluster fabric link for evidence
// that its L2 segment is not private to the two cluster peers (#18719).
//
// The #10105 zone-encoded fabric stamp is unauthenticated: any host that can
// put frames on the fabric segment can clone it. The deployment constraint
// (a private two-peer L2 domain) cannot be proven from software, but a
// violation can be OBSERVED: frames on the fabric parent whose Ethernet
// source is neither this node's fabric MAC, nor the peer's fabric MAC, nor an
// xpf synthetic stamp. Another host's ARP/ND/DHCP, a switch's own IP
// chatter on the fabric VLAN and a misplugged NIC all show up that way. An
// adjacent switch's STP/LACP/LLDP does NOT count: those go to IEEE 802.1
// link-constrained groups a bridge never relays, so they prove a bridge port,
// not a third host, and a fabric on a dedicated switch VLAN stays private.
//
// Cost: the watcher never touches the AF_XDP fast path. It reads an
// AF_PACKET tap on the fabric parent, which only sees frames the XDP shim
// hands to the kernel (ARP, LLDP, NDP, kernel-forwarded traffic), behind a
// kernel cBPF filter that discards every frame from the two known fabric
// MACs, so userspace wakes only for a candidate foreign source.
package fabricsegment

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// AlarmHold is how long a foreign source keeps the alarm raised after its
// last frame. A foreign speaker is a property of the plant, not of one
// packet, so the alarm outlives the frame long enough to be read.
const AlarmHold = 15 * time.Minute

// maxTrackedMACs bounds the per-link foreign-source table so a frame storm
// with random source MACs cannot grow memory. The count keeps counting.
const maxTrackedMACs = 8

// Link names one fabric link the watcher samples.
type Link struct {
	Name          string // fab0 / fab1
	Parent        string // Linux name of the fabric parent netdev
	ParentIfindex int
	LocalMAC      net.HardwareAddr
	PeerMAC       net.HardwareAddr
}

func (l Link) key() string {
	return fmt.Sprintf("%s|%s|%d|%s|%s", l.Name, l.Parent, l.ParentIfindex, l.LocalMAC, l.PeerMAC)
}

type sourceRecord struct {
	firstSeen time.Time
	lastSeen  time.Time
	frames    uint64
}

// Tracker accumulates foreign-source evidence for one link. It is safe for
// concurrent use: the sampler goroutine observes, status readers summarize.
type Tracker struct {
	link Link

	mu       sync.Mutex
	sources  map[string]*sourceRecord
	overflow uint64 // frames from sources beyond maxTrackedMACs
	raised   bool
	// onTransition is called (outside the lock) when the alarm raises or
	// clears. Nil means no callback.
	onTransition func(link Link, raised bool, summary string)
}

// NewTracker returns a tracker for link.
func NewTracker(link Link, onTransition func(Link, bool, string)) *Tracker {
	return &Tracker{link: link, sources: map[string]*sourceRecord{}, onTransition: onTransition}
}

// isXPFSyntheticSource reports whether src is in xpf's own synthetic MAC
// namespace: the V1 zone stamp and RETH virtual MACs (02:bf:72:*) and the V2
// NAT-scope stamp (02:bf:73:*). These are the PEER's stamped redirects (or a
// forgery of them, which a source check cannot tell apart). They are never
// evidence of a third speaker by themselves.
func isXPFSyntheticSource(src net.HardwareAddr) bool {
	return len(src) == 6 && src[0] == 0x02 && src[1] == 0xbf && (src[2] == 0x72 || src[2] == 0x73)
}

// IsForeignSource reports whether a frame with source src on this link is
// evidence of a speaker other than the two cluster peers.
func (t *Tracker) IsForeignSource(src net.HardwareAddr) bool {
	if len(src) != 6 {
		return false
	}
	// A group (multicast) source is malformed and an all-zero source is a
	// placeholder; neither names a speaker.
	if src[0]&1 != 0 || isZeroMAC(src) {
		return false
	}
	if macEqual(src, t.link.LocalMAC) || macEqual(src, t.link.PeerMAC) {
		return false
	}
	return !isXPFSyntheticSource(src)
}

// isLinkConstrainedGroup reports whether dst is in the IEEE 802.1Q reserved
// block 01:80:c2:00:00:00-0f (STP/RSTP, slow protocols such as LACP, 802.1X,
// LLDP). A conformant bridge never relays a frame to one of these, so such a
// frame proves only that an ADJACENT bridge port exists, not that a third
// host shares the segment. A fabric carried on a dedicated switch VLAN is
// still a private two-peer segment and must not alarm on its switch's
// BPDUs or LLDP.
func isLinkConstrainedGroup(dst net.HardwareAddr) bool {
	return len(dst) == 6 && dst[0] == 0x01 && dst[1] == 0x80 && dst[2] == 0xc2 &&
		dst[3] == 0 && dst[4] == 0 && dst[5] <= 0x0f
}

// ObserveFrame records one received Ethernet frame (destination at [0:6],
// source at [6:12]). A runt and a frame to an IEEE 802.1 link-constrained
// group are not evidence. Observe does not retain the slice, so frame may be
// a reused receive buffer.
func (t *Tracker) ObserveFrame(frame []byte, now time.Time) {
	if len(frame) < 12 || isLinkConstrainedGroup(net.HardwareAddr(frame[0:6])) {
		return
	}
	t.Observe(net.HardwareAddr(frame[6:12]), now)
}

// Observe records one received frame's source MAC at now.
func (t *Tracker) Observe(src net.HardwareAddr, now time.Time) {
	if !t.IsForeignSource(src) {
		return
	}
	key := src.String()
	t.mu.Lock()
	rec, ok := t.sources[key]
	switch {
	case ok:
		rec.lastSeen = now
		rec.frames++
	case len(t.sources) < maxTrackedMACs:
		t.sources[key] = &sourceRecord{firstSeen: now, lastSeen: now, frames: 1}
	default:
		t.overflow++
	}
	fire := !t.raised
	t.raised = true
	summary := t.summaryLocked(now)
	t.mu.Unlock()
	if fire && t.onTransition != nil {
		t.onTransition(t.link, true, summary)
	}
}

// Tick expires sources older than AlarmHold and clears the alarm when none
// remain. The sampler calls it on every receive timeout.
func (t *Tracker) Tick(now time.Time) {
	t.mu.Lock()
	for key, rec := range t.sources {
		if now.Sub(rec.lastSeen) > AlarmHold {
			delete(t.sources, key)
		}
	}
	if len(t.sources) == 0 {
		t.overflow = 0
	}
	fire := t.raised && len(t.sources) == 0
	if fire {
		t.raised = false
	}
	t.mu.Unlock()
	if fire && t.onTransition != nil {
		t.onTransition(t.link, false, "")
	}
}

// Alarm returns the operator-facing alarm line, or "" when not raised.
func (t *Tracker) Alarm(now time.Time) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.raised {
		return ""
	}
	return t.summaryLocked(now)
}

func (t *Tracker) summaryLocked(now time.Time) string {
	keys := make([]string, 0, len(t.sources))
	var last time.Time
	var frames uint64
	for key, rec := range t.sources {
		keys = append(keys, key)
		if rec.lastSeen.After(last) {
			last = rec.lastSeen
		}
		frames += rec.frames
	}
	sort.Strings(keys)
	frames += t.overflow
	more := ""
	if t.overflow > 0 {
		more = ", and more"
	}
	ago := now.Sub(last).Round(time.Second)
	if ago < 0 {
		ago = 0
	}
	return fmt.Sprintf("fabric link %s (%s) received %d frame(s) from source MAC(s) that are neither peer's fabric MAC (%s%s), last %s ago: "+
		"the fabric is not a private two-peer L2 segment, so the #10105 zone stamp is cloneable on it (#18719)",
		t.link.Name, t.link.Parent, frames, strings.Join(keys, ", "), more, ago)
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != 6 || len(b) != 6 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isZeroMAC(m net.HardwareAddr) bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}
	return true
}
