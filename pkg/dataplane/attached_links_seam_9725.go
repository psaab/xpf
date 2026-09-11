package dataplane

import "github.com/cilium/ebpf/link"

// CountEveryXDPLinkForTest makes AttachedXDPLinkCount count every recorded link as
// kernel-attached, and returns the function that undoes it. It is for tests in
// packages that record fake links through SetLinkForTest and have no kernel
// object to ask (#9725), as SetLinkForTest itself is:
//
//	t.Cleanup(dataplane.CountEveryXDPLinkForTest())
func CountEveryXDPLinkForTest() (restore func()) {
	prev := xdpLinkIfindexSeam
	xdpLinkIfindexSeam = func(link.Link) (uint32, error) { return 1, nil }
	return func() { xdpLinkIfindexSeam = prev }
}
