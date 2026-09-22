package dataplane

import (
	"sort"

	"github.com/cilium/ebpf/link"
)

// AttachedXDPLinkCount returns the number of XDP links this Manager records
// whose bpf_link still reports a non-zero attached-device ifindex from the
// kernel. The link map is only the set of candidates; Info().XDP().Ifindex is
// the authority. A failed or non-XDP read is counted as unattached so the
// daemon's transit gate fails closed on uncertainty.
//
// This is deliberately a snapshot, not a writer-maintained counter. A future
// detach path, device unregister, driver reset, process exit, or privileged
// cleanup can change kernel truth without running one of our writers. The daemon
// periodically calls this method; link-change notifications only wake an
// earlier read as a latency optimisation.
func (m *Manager) AttachedXDPLinkCount() int {
	if m == nil {
		return 0
	}
	count := 0
	for _, l := range m.XDPLinks() {
		if xdpLinkAttachedFn(l) {
			count++
		}
	}
	return count
}

// AttachedXDPIfindexes returns the tracked xpf XDP attachment ifindexes that
// the kernel still proves attached. It is the provenance-bearing companion to
// AttachedXDPLinkCount: callers may use the returned set to scope a kernel
// pinhole, but must not infer ownership from a global netlink XDP flag.
//
// The tracked map is only a candidate set. Both the bpf_link's reported
// ifindex and the tracked map key must agree before an ifindex is returned;
// disagreement or an Info failure is the conservative, no-pinhole result.
//
// #10519: detach-debt members are intentionally excluded even when kernel
// truth still proves their XDP link attached. Their accepted snapshot has
// already dropped the interface, but the flag-clear or substantive-Unpin arm
// failed before the link could be closed; returning it here would re-open the
// stale forward fence pinhole on every gate reassert. Copy the candidates and
// debt under m.mu, then perform kernel Info reads without holding m.mu.
func (m *Manager) AttachedXDPIfindexes() []int {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	links := make(map[int]link.Link, len(m.xdpLinks))
	for ifindex, l := range m.xdpLinks {
		links[ifindex] = l
	}
	debt := make(map[int]struct{}, len(m.detachDebt))
	for ifindex := range m.detachDebt {
		debt[ifindex] = struct{}{}
	}
	m.mu.Unlock()
	if len(links) == 0 {
		return nil
	}
	out := make([]int, 0, len(links))
	for ifindex, l := range links {
		if _, owed := debt[ifindex]; owed {
			continue
		}
		reported, ok := xdpLinkIfindexFn(l)
		if ok && reported == ifindex && ifindex > 0 {
			out = append(out, ifindex)
		}
	}
	sort.Ints(out)
	return out
}

// WithAttachedXDPFence runs fn while the Manager's XDP ownership read lease is
// held. The callback receives a kernel-truth ifindex snapshot and must complete
// the corresponding forward-fence installation and transit-open actuation
// before returning. XDP attach/detach writers hold the write lease across their
// kernel transition, so a detach cannot race from the snapshot through the
// fence/sysctl transition.
func WithAttachedXDPFence(m *Manager, fn func([]int) error) error {
	if m == nil || fn == nil {
		return nil
	}
	return m.withAttachedXDPFence(fn)
}

func (m *Manager) withAttachedXDPFence(fn func([]int) error) error {
	m.xdpOwnershipMu.RLock()
	defer m.xdpOwnershipMu.RUnlock()
	m.mu.Lock()
	cands := make([]struct {
		ifindex int
		l       link.Link
	}, 0, len(m.xdpLinks))
	for ifindex, l := range m.xdpLinks {
		if _, owed := m.detachDebt[ifindex]; owed {
			continue
		}
		cands = append(cands, struct {
			ifindex int
			l       link.Link
		}{ifindex: ifindex, l: l})
	}
	m.mu.Unlock()
	out := make([]int, 0, len(cands))
	for _, cand := range cands {
		reported, ok := xdpLinkIfindexFn(cand.l)
		if ok && reported == cand.ifindex && cand.ifindex > 0 {
			out = append(out, cand.ifindex)
		}
	}
	sort.Ints(out)
	return fn(out)
}

// SetAttachedLinksObserver installs a non-authoritative wake callback. The
// callback carries no count and must not be used as gate state: the daemon
// invokes AttachedXDPLinkCount again when it receives the wake, while its
// periodic tick remains the completeness guarantee.
func (m *Manager) SetAttachedLinksObserver(fn func()) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.attachedLinksObserver = fn
	m.mu.Unlock()
}

func (m *Manager) notifyAttachedLinksChanged() {
	if m == nil {
		return
	}
	m.mu.Lock()
	fn := m.attachedLinksObserver
	m.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// linkInfoIfindex is kept as a small testable production predicate: an Info
// failure, absent XDP metadata, and ifindex zero all mean the kernel cannot
// prove an attached program.
func linkInfoIfindex(l link.Link) (int, bool) {
	if l == nil {
		return 0, false
	}
	info, err := l.Info()
	if err != nil || info == nil {
		return 0, false
	}
	xdp := info.XDP()
	if xdp == nil || xdp.Ifindex == 0 {
		return 0, false
	}
	return int(xdp.Ifindex), true
}

func linkInfoAttached(l link.Link) bool {
	_, ok := linkInfoIfindex(l)
	return ok
}

// xdpLinkAttachedFn is a narrow test seam around the kernel Info read. Tests
// can model attached, detached, and uncertain links without CAP_BPF; production
// uses linkInfoAttached unchanged.
var xdpLinkAttachedFn = linkInfoAttached

// xdpLinkIfindexFn is the matching provenance seam for callers that need the
// actual kernel-reported ifindex rather than only a boolean count.
var xdpLinkIfindexFn = linkInfoIfindex
