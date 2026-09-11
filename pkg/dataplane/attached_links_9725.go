package dataplane

import (
	"errors"

	"github.com/cilium/ebpf/link"
)

// AttachedXDPLinkCount returns how many interfaces carry an XDP link this Manager
// attached, still holds, and the kernel still reports attached to a device. The
// daemon's #9725 transit gate opens kernel transit only while it is above zero
// (pkg/daemon/transit_closed_until_attach_9725.go).
//
// A pass that skips an interface it was handed never raises it. A detach lowers
// it, including the native-to-generic fallback's and the #5485 reconcile's after
// a snapshot publish. A link whose device the kernel unregistered (NIC removal,
// VF re-creation, a driver reload) keeps its handle and its map entry, but the
// kernel detached its program; such a link is not counted. What the count still
// does not see is stated with the gate.
func (m *Manager) AttachedXDPLinkCount() int {
	if m == nil {
		return 0
	}
	n := 0
	for _, l := range m.XDPLinks() {
		if xdpLinkAttached(l) {
			n++
		}
	}
	return n
}

// xdpLinkAttached reports whether the kernel still attaches l's program to a
// device: an XDP bpf_link whose device was unregistered reports ifindex 0. A link
// whose device cannot be read is not counted, so the gate fails closed.
func xdpLinkAttached(l link.Link) bool {
	ifindex, err := xdpLinkIfindexSeam(l)
	return err == nil && ifindex != 0
}

// errNotAnXDPLink is xdpLinkIfindexSeam's error for a link whose info carries no
// XDP section.
var errNotAnXDPLink = errors.New("link info has no XDP section")

// xdpLinkIfindexSeam reads the device ifindex the kernel reports for l. Tests
// replace only this read, because a fake link has no kernel object; the decision
// over its result, xdpLinkAttached, stays the production code.
var xdpLinkIfindexSeam = func(l link.Link) (uint32, error) {
	info, err := l.Info()
	if err != nil {
		return 0, err
	}
	x := info.XDP()
	if x == nil {
		return 0, errNotAnXDPLink
	}
	return x.Ifindex, nil
}
