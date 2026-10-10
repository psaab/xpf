package config

import "net"

// MaxRethCount is the largest supported chassis-cluster RETH count. RETH
// indexes range from zero through MaxRethCount-1.
const MaxRethCount = 128

// RethVirtualMAC returns the deterministic per-node, per-RETH virtual MAC.
// Its layout is 02:bf:72:CC:RR:II, where CC is the cluster ID, RR the
// redundancy-group ID, and II = 2*rethIndex + nodeID. This packs the 128
// supported RETH indexes and two node IDs into the final octet while preserving
// the existing MAC for reth0 on both nodes.
//
// Cluster ID and redundancy-group ID retain their commit-time one-octet bounds;
// RETH indexes come from Config.RethMACIndexes, and nodeID must be 0 or 1. The
// per-config mapping supports noncanonical but structurally valid RETH names.
func RethVirtualMAC(clusterID, rgID, rethIndex, nodeID int) net.HardwareAddr {
	return net.HardwareAddr{0x02, 0xbf, 0x72, byte(clusterID), byte(rgID), byte(2*rethIndex + nodeID)}
}
