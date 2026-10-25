//go:build !linux

package snmp

import (
	"net"
	"syscall"
)

// Non-Linux stub: SO_BINDTODEVICE / VRF listeners are Linux-only (the
// production target), so Bind serves a single unpinned listener and no
// pktinfo is captured or echoed. This file exists only so the package
// still type-checks on developer machines; socket_vrf.go's use of
// unix.SO_BINDTODEVICE already limited full builds to Linux.

type pktinfo struct {
	ifindex int
	dst     net.IP
}

func parsePktinfo([]byte) pktinfo { return pktinfo{} }

func (p pktinfo) oob() []byte { return nil }

func snmpListenSocketControl() func(string, string, syscall.RawConn) error {
	return nil
}

func snmpVRFPktinfoSocketControl(device string) func(string, string, syscall.RawConn) error {
	return snmpVRFSocketControl(device)
}
