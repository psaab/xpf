package config

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sort"
)

// Reportable source-NAT pool capacity (#7000).
//
// THE DEFECT THIS REPLACES. Six operator-facing surfaces each derived a pool's
// address cardinality as `len(pool.Addresses)` and multiplied it by the port
// range. That single expression is wrong in FOUR directions at once:
//
//  1. It reports capacity for a pool the dataplane REFUSED. A pool whose member
//     the Rust expander cannot honour installs no allocator at all, so any
//     non-zero figure is confidently wrong — including on the
//     `natPoolTotalPorts` Prometheus gauge, where it becomes the denominator of
//     a utilisation alert for a pool that can allocate nothing.
//  2. It UNDER-reports a prefix member. The expander enumerates every unique
//     address in the prefix (network and broadcast included), so a healthy
//     `203.0.113.0/24` installs 256 addresses and was reported as 1.
//  3. It MISSES the singular `address` field entirely. `SourceNATPoolMembers`
//     — the one answer to "what is in this pool", shared by the snapshot
//     builder and the unusable verdict — is `pool.Address` PLUS
//     `pool.Addresses`, so a pool configured with only the singular form
//     reported 0.
//  4. It OVER-reports duplicate or overlapping members. The dataplane keeps
//     only the first occurrence of each expanded address within a pool, so
//     capacity must count the union rather than each configured member.
//
// WHY A SINGLE SOURCE RATHER THAN AN AGREEMENT TEST. Two derivations of "how
// many addresses does this pool have" can never legitimately differ: there is
// one pool and one expander. So the divergence is always a bug, and the fix is
// to remove the second derivation rather than to bind the two. `NATPoolTotalPorts`
// already single-sources the MULTIPLICATION; this single-sources the
// CARDINALITY that was being fed into it.
//
// WHAT ZERO MEANS, AND WHY THE REASON COMES BACK WITH IT. A capacity of 0 is
// ambiguous on its own — no such pool, a pool with no members, a pool whose
// member is malformed, and a pool refused by the #6812 aggregate budget all
// produce it, and they have different operator remedies. Returning the count
// ALONE would collapse them, so this returns the reason alongside it and
// callers that can render it do. That is the same three-states discipline
// #6982 applied to the NAT64 budget, one layer out.

// SourceNATPoolReportableAddresses returns the unique expanded address
// cardinality an operator surface should report for a source-NAT pool, and the
// reason it is zero.
//
// A non-empty reason means the dataplane installs NO allocator for this pool,
// so the reportable capacity is 0 whatever its members say. An empty reason
// means the count is the unique expanded cardinality the dataplane installs.
//
// `overBudget` is `SourceNATAggregateOverBudgetPools(cfg)`; pass nil when the
// caller has no config-wide view, which degrades to the definition verdict
// alone rather than silently reporting an over-budget pool as healthy.
func SourceNATPoolReportableAddresses(pool *NATPool, poolName string, overBudget map[string]bool) (int, string) {
	if reason := SourceNATPoolDisarmedReason(pool, poolName, overBudget); reason != "" {
		return 0, reason
	}
	total := sourceNATPoolUniqueAddressCount(SourceNATPoolMembers(pool))
	maxInt := uint64(^uint(0) >> 1)
	if total > maxInt {
		return int(maxInt), ""
	}
	return int(total), ""
}

// SourceNATPoolReportablePorts is the port-capacity form of the same verdict:
// the reportable address count multiplied through the shared
// `NATPoolTotalPorts` arithmetic, plus the reason it is zero.
//
// Callers used to compute `NATPoolTotalPorts(low, high, len(pool.Addresses))`.
// The multiplication was never the wrong part.
func SourceNATPoolReportablePorts(pool *NATPool, poolName string, portLow, portHigh int, overBudget map[string]bool) (int64, string) {
	addrs, reason := SourceNATPoolReportableAddresses(pool, poolName, overBudget)
	if reason != "" {
		return 0, reason
	}
	return NATPoolTotalPorts(portLow, portHigh, addrs), ""
}

// sourceNATPoolAddressInterval is one member's inclusive address range after
// the same prefix expansion the dataplane performs. Merging these intervals
// counts overlap without materializing every address in a large pool.
type sourceNATPoolAddressInterval struct {
	width int
	lo    [16]byte
	hi    [16]byte
}

func sourceNATPoolAddressIntervalOf(member string) (sourceNATPoolAddressInterval, bool) {
	prefix, err := netip.ParsePrefix(member)
	if err != nil {
		addr, addrErr := netip.ParseAddr(member)
		if addrErr != nil {
			return sourceNATPoolAddressInterval{}, false
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	prefix = prefix.Masked()
	addr := prefix.Addr()
	hostBits := addr.BitLen() - prefix.Bits()
	if hostBits >= 64 || (uint64(1)<<uint(hostBits)) > MaxSourceNATPoolPrefixHosts {
		return sourceNATPoolAddressInterval{}, false
	}

	var interval sourceNATPoolAddressInterval
	var addrBits int
	if addr.Is4() {
		raw := addr.As4()
		interval.width = 4
		addrBits = 32
		copy(interval.lo[:4], raw[:])
	} else {
		raw := addr.As16()
		interval.width = 16
		addrBits = 128
		copy(interval.lo[:16], raw[:])
	}
	interval.hi = interval.lo
	for bit := prefix.Bits(); bit < addrBits; bit++ {
		interval.hi[bit/8] |= byte(1 << (7 - bit%8))
	}
	return interval, true
}

// sourceNATPoolUniqueAddressCount returns the union cardinality of the member
// ranges, saturating at MaxUint64 for a union too large to represent.
func sourceNATPoolUniqueAddressCount(members []string) uint64 {
	intervals := make([]sourceNATPoolAddressInterval, 0, len(members))
	for _, member := range members {
		if interval, ok := sourceNATPoolAddressIntervalOf(member); ok {
			intervals = append(intervals, interval)
		}
	}
	if len(intervals) == 0 {
		return 0
	}
	sort.Slice(intervals, func(i, j int) bool {
		a, b := intervals[i], intervals[j]
		if a.width != b.width {
			return a.width < b.width
		}
		if cmp := bytes.Compare(a.lo[:a.width], b.lo[:b.width]); cmp != 0 {
			return cmp < 0
		}
		return bytes.Compare(a.hi[:a.width], b.hi[:b.width]) < 0
	})

	total := uint64(0)
	current := intervals[0]
	for _, next := range intervals[1:] {
		if current.width == next.width &&
			bytes.Compare(next.lo[:next.width], current.hi[:current.width]) <= 0 {
			if bytes.Compare(next.hi[:next.width], current.hi[:current.width]) > 0 {
				current.hi = next.hi
			}
			continue
		}
		total = checkedAddU64(total, sourceNATPoolIntervalSize(current))
		current = next
	}
	return checkedAddU64(total, sourceNATPoolIntervalSize(current))
}

func sourceNATPoolIntervalSize(interval sourceNATPoolAddressInterval) uint64 {
	var difference [16]byte
	borrow := 0
	for i := interval.width - 1; i >= 0; i-- {
		d := int(interval.hi[i]) - int(interval.lo[i]) - borrow
		if d < 0 {
			d += 256
			borrow = 1
		} else {
			borrow = 0
		}
		difference[i] = byte(d)
	}
	carry := 1
	for i := interval.width - 1; i >= 0 && carry != 0; i-- {
		sum := int(difference[i]) + carry
		difference[i] = byte(sum)
		carry = sum >> 8
	}
	if carry != 0 {
		if interval.width < 8 {
			return uint64(1) << uint(interval.width*8)
		}
		return ^uint64(0)
	}

	start := interval.width - 8
	if start < 0 {
		start = 0
	}
	for _, high := range difference[:start] {
		if high != 0 {
			return ^uint64(0)
		}
	}
	var low [8]byte
	copy(low[8-(interval.width-start):], difference[start:interval.width])
	return binary.BigEndian.Uint64(low[:])
}

// sourceNATPoolMemberHosts is the host count one pool member expands to,
// mirroring the Rust `expand_pool_address` exactly.
//
// A bare address is 1. A CIDR enumerates `1 << host_bits` addresses — the
// network and broadcast addresses INCLUDED, because the expander pushes every
// value in the range and the allocator indexes all of them. A member the
// expander would refuse returns 0, but callers reach this only after
// SourceNATPoolDisarmedReason has cleared the pool, so that is a backstop
// rather than a live path: an unhonourable member makes the WHOLE pool
// unusable (`invalid_pool`), never a silently narrowed one.
func sourceNATPoolMemberHosts(addr string) int {
	p, err := netip.ParsePrefix(addr)
	if err != nil {
		// Not CIDR: a bare address counts once (and only if it parses).
		if _, aerr := netip.ParseAddr(addr); aerr != nil {
			return 0
		}
		return 1
	}
	addrBits := 32
	if p.Addr().Is6() {
		addrBits = 128
	}
	hostBits := addrBits - p.Bits()
	// BEHAVIOURALLY REDUNDANT, AND SAID SO RATHER THAN CLAIMED OTHERWISE.
	//
	// This guard mirrors the Rust early-out, but unlike the Rust one it changes
	// no output here. Go DEFINES an over-wide shift as 0 (it is not UB and does
	// not wrap), and 0 fails the `count > MaxSourceNATPoolPrefixHosts` check
	// below exactly as a huge value does, so both paths return 0 for every
	// hostBits >= 64. Measured at 63 / 64 / 65 / 128.
	//
	// An earlier revision of this comment said the guard "prevents an over-wide
	// shift ... which would UNDER-count". That was FALSE: under-counting to 0 is
	// precisely the right answer for an over-cap prefix, which is why the cap
	// check already produces it. #7000's mutation cell M5 relaxed this bound to
	// `>= 1024` and the whole suite stayed GREEN — an unbound guard, correctly
	// reported as an escape rather than dressed up as a red.
	//
	// It is kept as a structural guard for a refactor that moves or widens the
	// cap check, and for parity with the Rust expander it mirrors — not because
	// it is load-bearing today. Do not write a test claiming it is; there is no
	// input that distinguishes the two.
	if hostBits < 0 || hostBits >= 64 {
		return 0
	}
	count := uint64(1) << uint(hostBits)
	if count > MaxSourceNATPoolPrefixHosts {
		return 0
	}
	return int(count)
}
