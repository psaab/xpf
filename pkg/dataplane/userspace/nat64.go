package userspace

import (
	"net"

	"github.com/psaab/xpf/pkg/config"
)

// nat64PortLow / nat64PortHigh mirror the FIXED NAT64 translated-port range the
// Rust dataplane's per-prefix PortAllocator uses (userspace-dp/src/nat64.rs
// NAT64_PORT_LOW / NAT64_PORT_HIGH). Deterministic NAPT64 (mode 2) block
// boundaries MUST be computed against THIS range, not the source pool's own
// `port` range (which the NAT64 allocator ignores), so the Go-computed
// blocks_per_ip aligns with the block boundaries the allocator walks (#4559).
const (
	nat64PortLow  = 1024
	nat64PortHigh = 65535
)

// deterministicNAT64V6Fields computes the mode-2 (IPv6-subscriber / NAPT64)
// deterministic block-allocation wire fields for a source pool referenced by a
// NAT64 rule-set (#4559). It returns ok=false (leaving the pool on the
// round-robin path + the commit-time advisory) unless the pool carries `port
// deterministic block-size <n>` with an IPv6 host CIDR of a SUPPORTED prefix
// length (/32 or /64 — the only lengths that map to a 32-bit subscriber word,
// matching the retired-eBPF nat_pool_alloc_deterministic_v6 split) and the
// block math is non-degenerate. host_count is NOT returned: the Rust side
// derives it from the parsed pool size (pool-bounded), avoiding a Go/Rust
// pool-count skew.
func deterministicNAT64V6Fields(pool *config.NATPool) (blockSize, blocksPerIP uint16, prefixLen uint8, baseStr string, ok bool) {
	if pool == nil || pool.Deterministic == nil {
		return 0, 0, 0, "", false
	}
	det := pool.Deterministic
	if det.BlockSize <= 0 || det.HostAddress == "" {
		return 0, 0, 0, "", false
	}
	ip, hostNet, err := net.ParseCIDR(det.HostAddress)
	if err != nil {
		return 0, 0, 0, "", false
	}
	// Must be an IPv6 host CIDR (a v4 host is mode 1, handled on the source-NAT
	// snapshot). net.ParseCIDR on an IPv4-mapped literal yields a 4-byte IP;
	// require a genuine 16-byte IPv6 address with no v4 projection.
	if ip.To4() != nil || ip.To16() == nil {
		return 0, 0, 0, "", false
	}
	ones, bits := hostNet.Mask.Size()
	if bits != 128 || (ones != 32 && ones != 64) {
		return 0, 0, 0, "", false
	}
	portRange := nat64PortHigh - nat64PortLow + 1
	if det.BlockSize > portRange {
		return 0, 0, 0, "", false
	}
	bpi := portRange / det.BlockSize
	if bpi <= 0 || bpi > 0xFFFF {
		return 0, 0, 0, "", false
	}
	// Emit the canonical network base (masked), so the dataplane's word
	// extraction and reverse reconstruct against the same base the operator
	// configured.
	return uint16(det.BlockSize), uint16(bpi), uint8(ones), hostNet.IP.String(), true
}

func buildNAT64Snapshots(cfg *config.Config) []NAT64RuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.NAT64) == 0 {
		return nil
	}
	// `security nat natv6v4 no-v6-frag-header` is a global option, but the
	// dataplane consumes NAT64 state per rule-set. Replicate the flag onto
	// every emitted rule so the IPv6->IPv4 translator can honor the explicit
	// DF-clear override. Without it, RFC 7915 5.1 selects DF from the translated
	// IPv4 total length (clear through 1260 bytes, set above).
	noV6FragHeader := cfg.Security.NAT.NATv6v4 != nil && cfg.Security.NAT.NATv6v4.NoV6FragHeader
	out := make([]NAT64RuleSnapshot, 0, len(cfg.Security.NAT.NAT64))
	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil || rs.Prefix == "" {
			continue
		}
		// #2214: initialize non-nil so a rule with no resolvable source pool
		// marshals `pool_addresses` as `[]`, never JSON `null`. The field has
		// no `,omitempty` (an empty pool is still a meaningful "no source-pool
		// resolved" state the dataplane must see), and the Rust `Vec<String>`
		// rejects an explicit null — which aborts the whole snapshot decode and
		// kills ALL transit (#1961 no-transit signature).
		poolAddresses := []string{}
		// #4559: mode-2 deterministic NAPT64 params, resolved from the referenced
		// source pool. Zero unless the pool has an enforced IPv6-host `port
		// deterministic` stanza (see deterministicNAT64V6Fields); the round-robin
		// path is then byte-identical to pre-#4559.
		var detBlockSize, detBlocksPerIP uint16
		var detHostPrefixLen uint8
		var detHostBaseV6 string
		if rs.SourcePool != "" {
			if pool, ok := cfg.Security.NAT.SourcePools[rs.SourcePool]; ok && pool != nil {
				if pool.Address != "" {
					poolAddresses = append(poolAddresses, pool.Address)
				}
				poolAddresses = append(poolAddresses, pool.Addresses...)
				if bs, bpi, pl, base, okDet := deterministicNAT64V6Fields(pool); okDet {
					detBlockSize, detBlocksPerIP, detHostPrefixLen, detHostBaseV6 = bs, bpi, pl, base
				}
			}
		}
		out = append(out, NAT64RuleSnapshot{
			Name:                       rs.Name,
			Prefix:                     config.NormaliseNAT64PrefixForSnapshot(rs.Prefix),
			PoolAddresses:              poolAddresses,
			NoV6FragHeader:             noV6FragHeader,
			DeterministicBlockSize:     detBlockSize,
			DeterministicBlocksPerIP:   detBlocksPerIP,
			DeterministicHostPrefixLen: detHostPrefixLen,
			DeterministicHostBaseV6:    detHostBaseV6,
		})
	}
	return out
}
