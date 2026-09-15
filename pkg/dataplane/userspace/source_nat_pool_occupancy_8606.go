package userspace

// Source-NAT pool occupancy: the ONE resolution of "how many ports is this
// pool using", shared by every surface that reports it.
//
// #8606. Before this, four surfaces answered the question independently and
// three of them answered it with a RANDOM NUMBER.
//
// `Manager.SeedNATPortCounters` seeds the legacy `nat_port_counters` per-CPU
// array with `rand.Uint64()` — correctly, and on purpose: it makes the map a
// randomly-offset rolling allocation CURSOR so a restarted daemon does not
// re-issue ports a peer still has in ESTABLISHED state. It was never an
// occupancy count.
//
// The eBPF programs that advanced that cursor were deleted with the eBPF
// dataplane (#1373/#1476). `nat_port_counters` appears nowhere in
// `userspace-dp/src` or `userspace-xdp/src`, so on the only runtime forwarding
// path the product has, a read of it returns the seed unmodified. Reported as
// occupancy that is a uniformly random `uint64`, which then converted through
// an unchecked `int64(cnt)` and saturated to `math.MinInt32` — the
// `Ports allocated: -2147483648` this issue was filed for. The utilization
// string, computed from the UNCLAMPED value, varied with each restart's fresh
// seed while the clamped field sat pinned; two symptoms, one cause.
//
// The helper has always known the real answer and already publishes it as
// `xpf_userspace_snat_pool_used_ports`. This is that source, exposed once.
//
// Why the legacy read is not kept as a fallback: a fallback exists to avoid a
// blank surface, and blankness is only worse than a number when the number is
// TRUE. Falling back to the seed reports a random value as occupancy, which is
// strictly worse than reporting nothing — it is indistinguishable from a
// measurement. #7473 settled the same argument for the disarmed-pool zero
// ("a missing series says 'not installed', a 0 says 'measured, and nothing is
// used', and monitoring cannot tell the second from health"), and the argument
// is stronger here, not weaker.

// SourceNATPoolOccupancy indexes a status snapshot's source-NAT pools by pool
// name.
//
// Deduplicated, never summed: rules sharing a pool share one
// `Arc<PortAllocatorShared>` in the helper and therefore report IDENTICAL
// `UsedPorts`, so summing across rules multiplies the occupancy by the number
// of referencing rules. Among same-name rows the CONSTRUCTED allocator wins
// (`MaxTrackedFlows>0`, tie → first) — a poisoned rule (#9874) keeps its
// pool_mode but builds no allocator, and its default-zeros row must not
// shadow the live one. This is the same contract `AppliedNATView.Pools`
// documents (#9902 F-026 keeps the two in lockstep); both exist because the
// alarm monitor needs the cached applied view while the reporting surfaces
// need the live status.
func SourceNATPoolOccupancy(status ProcessStatus) map[string]SourceNATPoolStatus {
	if len(status.SourceNATPools) == 0 {
		return nil
	}
	pools := make(map[string]SourceNATPoolStatus, len(status.SourceNATPools))
	selectedMax := make(map[string]uint64, len(status.SourceNATPools))
	for _, p := range status.SourceNATPools {
		if p.PoolName == "" {
			continue
		}
		if _, seen := pools[p.PoolName]; seen {
			if selectedMax[p.PoolName] > 0 || p.MaxTrackedFlows == 0 {
				continue
			}
		}
		selectedMax[p.PoolName] = p.MaxTrackedFlows
		pools[p.PoolName] = p
	}
	return pools
}
