package api

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// listener_vrf_16709.go — #16709: SO_BINDTODEVICE-scoped binds for
// web-management legs whose address lives in a VRF.
//
// fxp0 (and every management-class interface) is enslaved to vrf-mgmt, and
// a tenant interface can be enslaved to vrf-<instance>. An address on a
// VRF slave exists only in that VRF's local table, so the pre-#16709
// unscoped net.Listen("tcp", "<slave-ip>:443") was refused with
// EADDRNOTAVAIL on every apply: `web-management http|https interface
// fxp0.0` — the usual Junos idiom — could never serve IPv4 or global
// IPv6, and because the HTTP IPv4 leg is first, HTTP Start failed with
// nothing serving. tcp_l3mdev_accept does not help: it lets a WILDCARD
// socket accept through a VRF, but a bind to a specific VRF-slave
// address is still checked against the main local table.
//
// The fix scopes such legs to the VRF MASTER device (vrf-mgmt /
// vrf-<name>), exactly as the grpcapi fabric listener does
// (pkg/grpcapi/server.go): SO_BINDTODEVICE on the master makes the
// VRF's local table authoritative for the bind and for accepted
// traffic. Default-VRF legs stay unscoped. A link-local leg already
// carries its zone (the slave interface name); binding it through the
// VRF master as well is harmless and keeps one scope per interface.

// bindDeviceMap is the immutable address->device snapshot behind
// Server.bindDevices. It is replaced wholesale by SetBindDevices and
// never mutated in place, so concurrent binds read it lock-free.
type bindDeviceMap struct {
	m map[string]string
}

func cloneBindDevices(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for addr, dev := range in {
		if dev != "" {
			out[addr] = dev
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// bindDeviceFor returns the SO_BINDTODEVICE device for addr, or "" when
// the leg binds unscoped (no entry, nil snapshot, or bare fixture).
func (s *Server) bindDeviceFor(addr string) string {
	p := s.bindDevices.Load()
	if p == nil {
		return ""
	}
	return p.m[addr]
}

// SetBindDevices replaces the address->device scope snapshot. The
// daemon calls it (via the management reconciler) BEFORE the leg
// reconciles that consume it, so a scope change and the rebind it
// forces land in the same reconcile pass. Legs whose recorded scope
// already matches are not bounced — reconcileLegsLocked compares the
// live legs' scopes against this snapshot.
func (s *Server) SetBindDevices(m map[string]string) {
	cloned := cloneBindDevices(m)
	if cloned == nil {
		s.bindDevices.Store(nil)
		return
	}
	s.bindDevices.Store(&bindDeviceMap{m: cloned})
}

// BindDevices returns a copy of the current scope snapshot (nil when
// no leg is device-scoped). Used by the daemon's endpoint fingerprint
// and by tests; the copy keeps the stored map immutable.
func (s *Server) BindDevices() map[string]string {
	p := s.bindDevices.Load()
	if p == nil || len(p.m) == 0 {
		return nil
	}
	return cloneBindDevices(p.m)
}

// listenAddr binds addr through the configured listener factory, or —
// when addr is device-scoped and no factory was injected — through a
// SO_BINDTODEVICE ListenConfig. An injected ListenFunc (tests) always
// wins: it models bind outcomes and must not be bypassed by a real
// socket option. Production never sets ListenFunc, so the VRF scope is
// applied on every production bind of a scoped address.
//
// Every production bind site (Start, reconcileLegsLocked,
// bindListeners/Run, HTTPS cert recovery) goes through here so no leg
// can silently revert to the unscoped bind that #16709 fixes.
func (s *Server) listenAddr(addr string) (net.Listener, error) {
	dev := s.bindDeviceFor(addr)
	if dev == "" || s.listenIsCustom() {
		ln, err := s.listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		s.recordLegDevice(addr, dev)
		return ln, nil
	}
	lc := net.ListenConfig{Control: bindToDeviceControl(dev)}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("api: bind %q scoped to device %q: %w", addr, dev, err)
	}
	s.recordLegDevice(addr, dev)
	return ln, nil
}

// listenIsCustom reports whether a test injected Config.ListenFunc.
// NewServer records the production default separately (customListen)
// so this never compares function values.
func (s *Server) listenIsCustom() bool {
	return s.customListen
}

// bindToDeviceControl sets SO_BINDTODEVICE before bind, mirroring
// pkg/grpcapi's fabric listener and pkg/snmp's socket control. The
// socket error is propagated: a failed BINDTODEVICE is the whole point
// of this control, and swallowing it would recreate the unscoped bind
// under a scoped name.
func bindToDeviceControl(device string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
		}); err != nil {
			return fmt.Errorf("api: bind socket to device %q: %w", device, err)
		}
		if sockErr != nil {
			return fmt.Errorf("api: bind socket to device %q: %w", device, sockErr)
		}
		return nil
	}
}

// --- live-leg scope bookkeeping -------------------------------------
//
// reconcileLegsLocked adopts a serving leg whose ADDRESS matches the
// desired set (#14983). Address alone is no longer identity once scopes
// exist: a leg bound unscoped (or to a different device) at the same
// address must be replaced when the desired scope changes, or a VRF
// enslavement change would leave the old socket serving. legDevices
// records, per live leg address, the device that leg was actually
// bound with ("" = unscoped). Every bind of a live leg goes through
// listenAddr with lifeMu held, so plain map access under lifeMu is
// safe; entries for retired addresses are pruned when a leg set is
// replaced.

// recordLegDevice records the scope a just-bound live leg carries.
// Start/reconcile/cert-recovery callers hold lifeMu. bindListeners
// (the Run path) binds before the server is shared with any other
// goroutine, so the unsynchronized write is safe there too; no caller
// binds concurrently with a reconcile.
func (s *Server) recordLegDevice(addr, dev string) {
	if s.legDevices == nil {
		s.legDevices = make(map[string]string)
	}
	s.legDevices[addr] = dev
}

// legDeviceLocked returns the device the live leg at addr was bound
// with. Caller holds lifeMu.
func (s *Server) legDeviceLocked(addr string) string {
	return s.legDevices[addr]
}

// pruneLegDevicesLocked rebuilds the scope records from the legs now
// installed: retained legs keep their recorded scope, replaced legs
// were re-recorded by their bind, and retired addresses drop out.
// Caller holds lifeMu after installing a new leg set.
func (s *Server) pruneLegDevicesLocked(serving []string) {
	if len(s.legDevices) == 0 {
		return
	}
	live := make(map[string]string, len(serving))
	for _, addr := range serving {
		live[addr] = s.legDevices[addr]
	}
	s.legDevices = live
}
