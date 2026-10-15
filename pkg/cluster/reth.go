// Package cluster RETH (Redundant Ethernet) identity helpers.
// RETH MAC programming and VIP ownership live in pkg/daemon and
// pkg/vrrp; this file only carries the deterministic identity helpers.
package cluster

import (
	"net"

	"github.com/psaab/xpf/pkg/config"
)

// RethMAC returns the deterministic virtual MAC for a RETH interface.
// Format: 02:bf:72:CC:RR:(2*reth-index+node-id), with RETH index 0..127.
// Config.RethMACIndexes preserves that suffix for canonical rethN owners and
// assigns stable free indexes to other structurally valid owner names.
// Each node gets a per-RETH MAC to avoid FDB conflicts when both nodes' members
// are on the same L2 domain (e.g. SR-IOV VFs from the same PF, or same physical
// switch). VRRP + gratuitous NA handle failover; RA goodbye packets handle IPv6
// default gateway transitions.
//
// This is a DELIBERATE deviation from RFC 5798 §7.3, which specifies a SHARED
// virtual-router MAC (00-00-5E-00-01-{VRID} v4 / 00-00-5E-00-02-{VRID} v6) that
// both routers use, so the virtual router's L2 identity survives a failover
// untouched. Two consequences follow from not doing that, and both are accepted
// rather than overlooked (#5091):
//
//   - Failover CHANGES the L2 identity, so recovery rides on the GARP/NA burst
//     updating peer caches and switch FDBs instead of the address never moving.
//     ReconcileVIPs bumps garpEpoch and forces a burst precisely because the MAC
//     just changed (#2081) — an update-the-peers mechanism, not an
//     identity-preserving one.
//   - xpf cannot form a virtual router with a third-party VRRP speaker, which
//     expects the shared MAC. RETH VRRP is an xpf-to-xpf mechanism between the
//     two chassis of one cluster, not general VRRP interop.
//
// Do not "fix" this to the RFC MAC without solving the FDB problem first: a
// shared MAC on two member interfaces in one L2 domain makes the switch see one
// address on two ports. Operator-facing statement: docs/feature-coverage.md.
func RethMAC(clusterID, rgID, rethIndex, nodeID int) net.HardwareAddr {
	// #8340 (K18/K105): one construction, in the leaf package the dataplane's
	// recovery search can also reach.
	return config.RethVirtualMAC(clusterID, rgID, rethIndex, nodeID)
}

// StableRethLinkLocal returns a deterministic link-local IPv6 address shared
// by both cluster nodes for the same RETH interface. Used as the RA source
// address so hosts see a stable IPv6 router identity across failover.
// Format: fe80::bf72:CC:RR (clusterID, rgID — no nodeID component).
// This address sorts lower than EUI-64 link-locals derived from per-node
// RethMAC, so ndp.Listen and resolveIPv6LinkLocal will prefer it.
func StableRethLinkLocal(clusterID, rgID int) net.IP {
	return net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		0, 0, 0xbf, 0x72, 0, byte(clusterID), 0, byte(rgID)}
}

// IsStableRethLinkLocal returns true if the address matches the stable RETH
// link-local pattern (fe80::00:00:bf:72:...).
func IsStableRethLinkLocal(ip net.IP) bool {
	ip = ip.To16()
	return len(ip) == 16 &&
		ip[0] == 0xfe && ip[1] == 0x80 &&
		ip[8] == 0 && ip[9] == 0 &&
		ip[10] == 0xbf && ip[11] == 0x72
}
