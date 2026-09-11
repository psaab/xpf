// Package cluster RETH (Redundant Ethernet) failover management.
// Controls active/passive bond members based on redundancy group state.
package cluster

import (
	"fmt"
	"github.com/psaab/xpf/pkg/config"
	"log/slog"
	"net"
	"sync"

	"github.com/vishvananda/netlink"
)

// RethMapping maps a RETH interface to its redundancy group.
type RethMapping struct {
	RethName      string
	RedundancyGrp int
	Members       []string // physical member interface names
}

// RethController manages RETH bond member activation/deactivation
// based on cluster redundancy group state transitions.
type RethController struct {
	nlHandle *netlink.Handle
	mappings []RethMapping
	mu       sync.Mutex
}

// NewRethController creates a RETH failover controller.
func NewRethController() (*RethController, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("reth controller netlink: %w", err)
	}
	return &RethController{nlHandle: h}, nil
}

// Close releases resources.
func (rc *RethController) Close() {
	if rc.nlHandle != nil {
		rc.nlHandle.Close()
	}
}

// SetMappings updates the RETH-to-RG mappings.
func (rc *RethController) SetMappings(mappings []RethMapping) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.mappings = mappings
}

// HandleStateChange processes a cluster state change event.
// Physical member interfaces are kept UP on both nodes so VRRP can
// send advertisements. No bond devices — VRRP runs directly on physical.
func (rc *RethController) HandleStateChange(event ClusterEvent) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	for _, m := range rc.mappings {
		if m.RedundancyGrp != event.GroupID {
			continue
		}
		if rc.nlHandle == nil {
			continue
		}
		// Bring up physical member interfaces (VRRP needs them UP on both nodes)
		for _, member := range m.Members {
			link, err := rc.nlHandle.LinkByName(member)
			if err != nil {
				continue
			}
			rc.nlHandle.LinkSetUp(link)
		}
		slog.Info("reth physical members UP", "reth", m.RethName, "rg", m.RedundancyGrp)
	}
}

// RethIPs returns the IP addresses on a RETH's physical member interface.
func (rc *RethController) RethIPs(rethName string) ([]net.IP, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	for _, m := range rc.mappings {
		if m.RethName == rethName && len(m.Members) > 0 {
			link, err := rc.nlHandle.LinkByName(m.Members[0])
			if err != nil {
				return nil, fmt.Errorf("physical member %s for reth %s not found: %w", m.Members[0], rethName, err)
			}
			addrs, err := rc.nlHandle.AddrList(link, netlink.FAMILY_ALL)
			if err != nil {
				return nil, fmt.Errorf("addrs on %s: %w", m.Members[0], err)
			}
			var ips []net.IP
			for _, addr := range addrs {
				if addr.IP.To4() == nil && addr.IP.IsLinkLocalUnicast() {
					continue
				}
				ips = append(ips, addr.IP)
			}
			return ips, nil
		}
	}
	return nil, fmt.Errorf("reth %s not found", rethName)
}

// RethMAC returns the deterministic virtual MAC for a RETH interface.
// Format: 02:bf:72:CC:RR:NN (locally-administered, cluster_id, rg_id, node_id).
// Each node gets a unique MAC per RETH to avoid FDB conflicts when both
// nodes' member interfaces are on the same L2 domain (e.g. SR-IOV VFs
// from the same PF, or same physical switch). VRRP + gratuitous NA handle
// failover; RA goodbye packets handle IPv6 default gateway transitions.
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
func RethMAC(clusterID, rgID, nodeID int) net.HardwareAddr {
	// #8340 (K18/K105): one construction, in the leaf package the dataplane's
	// recovery search can also reach. `pkg/cluster` imports `pkg/dataplane`, so
	// the dependency could only go this way round — which is why the search key
	// and the thing it searches for had been written twice.
	return config.RethVirtualMAC(clusterID, rgID, nodeID)
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

// IsVirtualRethMAC returns true if the MAC matches the virtual RETH pattern (02:bf:72:...).
func IsVirtualRethMAC(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0] == 0x02 && mac[1] == 0xbf && mac[2] == 0x72
}

// FormatStatus returns RETH interface status for display.
func (rc *RethController) FormatStatus() string {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if len(rc.mappings) == 0 {
		return "No RETH interfaces configured\n"
	}

	var result string
	result += fmt.Sprintf("%-12s %-8s %-10s %s\n", "Interface", "RG", "Status", "Physical")
	for _, m := range rc.mappings {
		status := "unknown"
		if rc.nlHandle != nil && len(m.Members) > 0 {
			link, err := rc.nlHandle.LinkByName(m.Members[0])
			if err == nil {
				if LinkAttrsUp(link.Attrs()) {
					status = "up"
				} else {
					status = "down"
				}
			} else {
				status = "missing"
			}
		}
		members := ""
		for i, mem := range m.Members {
			if i > 0 {
				members += ", "
			}
			members += mem
		}
		result += fmt.Sprintf("%-12s %-8d %-10s %s\n", m.RethName, m.RedundancyGrp, status, members)
	}
	return result
}
