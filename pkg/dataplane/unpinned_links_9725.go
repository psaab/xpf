package dataplane

import (
	"fmt"
	"os"
	"path/filepath"
)

// UnpinnedAttachedXDPLinks returns how many of the links AttachedXDPLinkCount
// counts carry NO bpffs link pin, and so are detached by the kernel the moment
// this process closes its handle (#9725).
//
// It exists for ONE decision: whether a hitless stop may leave kernel transit
// open. A hitless stop closes Go handles and keeps the shim running, and
// daemon_run_shutdown.go leaves forwarding as it is on that path because "the
// dataplane stays attached and the shim keeps dropping transit" (#9686). That
// premise is a claim about PINS, and it is not always true:
//
//   - the pin is best effort. AttachXDP logs a failed Pin at Warn and returns
//     success, so a link can be attached and unpinned.
//   - removeUserspaceShimXDPLinkPins deletes every xdp_* pin at the start of a
//     compile and the attach re-pins afterwards, so a stop that lands in that
//     window, or after an attach that failed, finds live links with no pins.
//
// In both shapes Close() detaches the programs and the node keeps forwarding
// transit with nothing adjudicating it, for the whole downtime and into the next
// start. Counting them lets the shutdown close the gate in exactly those cases
// and leave a true hitless upgrade alone.
//
// A link the kernel has already detached is not counted: it is not forwarding
// anything, and AttachedXDPLinkCount does not count it either.
func (m *Manager) UnpinnedAttachedXDPLinks() int {
	if m == nil {
		return 0
	}
	n := 0
	for ifindex, l := range m.XDPLinks() {
		if !xdpLinkAttached(l) {
			continue
		}
		if !xdpLinkPinnedSeam(ifindex) {
			n++
		}
	}
	return n
}

// xdpLinkPinnedSeam reports whether ifindex's XDP link pin is present. Tests
// replace only this lookup, because a fake link has no bpffs object; the
// decision over its result stays production code, as with xdpLinkIfindexSeam.
var xdpLinkPinnedSeam = func(ifindex int) bool {
	_, err := os.Stat(filepath.Join(linkPinPath, xdpLinkPinName(ifindex)))
	return err == nil
}

// xdpLinkPinName is the pin file name AttachXDP writes for ifindex. It is shared
// so the pin the attach creates and the pin this check looks for cannot drift
// apart silently.
func xdpLinkPinName(ifindex int) string {
	return fmt.Sprintf("xdp_%d", ifindex)
}

// SetXDPLinkPinnedForTest makes the pin lookup answer pinned for exactly the
// given ifindexes, and returns the function that restores the previous lookup.
func SetXDPLinkPinnedForTest(pinned map[int]bool) (restore func()) {
	prev := xdpLinkPinnedSeam
	xdpLinkPinnedSeam = func(ifindex int) bool { return pinned[ifindex] }
	return func() { xdpLinkPinnedSeam = prev }
}
