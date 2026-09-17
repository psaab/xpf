package dataplane

import "github.com/cilium/ebpf/link"

// AttachedXDPLinkCount returns the number of XDP links this Manager records
// whose bpf_link still reports a non-zero attached-device ifindex from the
// kernel. The link map is only the set of candidates; Info().XDP().Ifindex is
// the authority. A failed or non-XDP read is counted as unattached so the
// daemon's transit gate fails closed on uncertainty.
//
// This is deliberately a snapshot, not a writer-maintained counter. A future
// detach path, device unregister, driver reset, process exit, or privileged
// cleanup can change kernel truth without running one of our writers. The
// daemon periodically calls this method; link-change notifications only wake
// an earlier read as a latency optimisation.
func (m *Manager) AttachedXDPLinkCount() int {
	if m == nil {
		return 0
	}
	links := m.XDPLinks()
	count := 0
	for _, l := range links {
		if xdpLinkAttachedFn(l) {
			count++
		}
	}
	return count
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

// linkInfoAttached is kept as a small testable production predicate: an Info
// failure, absent XDP metadata, and ifindex zero all mean the kernel cannot
// prove an attached program.
func linkInfoAttached(l link.Link) bool {
	if l == nil {
		return false
	}
	info, err := l.Info()
	if err != nil || info == nil {
		return false
	}
	xdp := info.XDP()
	return xdp != nil && xdp.Ifindex != 0
}

// xdpLinkAttachedFn is a narrow test seam around the kernel Info read. Tests
// can model attached, detached, and uncertain links without CAP_BPF; production
// uses linkInfoAttached unchanged.
var xdpLinkAttachedFn = linkInfoAttached
