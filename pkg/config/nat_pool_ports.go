package config

import (
	"fmt"
	"sort"
)

// NATPoolTotalPorts is the SINGLE source of truth for a source-NAT pool's
// translation capacity: the size of its port window times its address count.
//
// It exists because the formula had been written out five times — the gRPC
// GetNATPoolStats handler, the REST natPoolStatsHandler, the Prometheus NAT
// collector, and both CLI `show security nat source pool` renders — and had
// already diverged. Only REST carried the portHigh >= portLow guard (#6553);
// the other four computed (portHigh - portLow + 1) directly, so a reversed
// window yields a NEGATIVE count that then flows into the availability and
// utilisation arithmetic. On the gRPC path clampInt32 saturates that to
// MinInt32 and the pool renders a large negative total with utilisation stuck
// at "0.0%".
//
// Reachability of a reversed window is deliberately not claimed here.
// parseSourcePoolPortRange fails closed on a reversed `port` leaf and
// validateSourceNATPoolStrict hard-rejects at commit (#5457), so the strict
// path should not produce one; the tolerant load / peer-sync path is the
// residual, and this guard is cheap regardless. What IS certain is that four
// surfaces disagreeing about one formula is a defect on its own terms — the
// point of centralising is that the next reader cannot reintroduce the
// divergence.
//
// Returns int64: (portHigh - portLow + 1) * addrCount can exceed int32 for a
// large pool (a /16 over the default 64512-port window is ~4.2e9). Callers
// storing into an int32 field must saturate rather than cast.
func NATPoolTotalPorts(portLow, portHigh, addrCount int) int64 {
	if portHigh < portLow || addrCount <= 0 {
		return 0
	}
	return int64(portHigh-portLow+1) * int64(addrCount)
}

// validateNATPoolAddressRangeStrict hard-rejects a NAT pool carrying an
// `address <low> to <high>` range larger than the 256-address expansion cap
// (#8814).
//
// The cap used to be raised as a compile error inside expandAddressRange, which
// put it on the LENIENT path as well as the strict one -- the security compiler
// chain (compileSecurity -> compileNATSource -> appendPoolAddresses) carries no
// compileOpts, so nothing could downgrade it. A persisted config with an
// oversized range failed to LOAD, which is precisely what CompileConfigLenient
// exists to prevent.
//
// Now the compiler RECORDS the range and this gate rejects it, so:
//
//	strict (commit / commit-check)   REJECTS, with the size in the message
//	tolerant (load / peer-sync)      warns; the pool loads without that range
//
// The pool keeps every OTHER address it was given -- an oversized range is
// omitted, not fatal to the pool -- so a config that mixes a valid range with an
// oversized one still boots with the valid one installed.
func validateNATPoolAddressRangeStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(kind string, pools map[string]*NATPool) error {
		names := make([]string, 0, len(pools))
		for name := range pools {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			pool := pools[name]
			if pool == nil {
				continue
			}
			if len(pool.OversizedAddressRanges) > 0 {
				return fmt.Errorf(
					"security nat %s pool %q address range %s; a pool address range expands to one "+
						"address per IP and is capped at 256 — narrow the range, or list the "+
						"addresses individually",
					kind, name, pool.OversizedAddressRanges[0])
			}
			// #15674: invalid range (non-host mask, malformed, mixed
			// family, reversed) recorded by the compiler.
			if len(pool.InvalidAddressRanges) > 0 {
				return fmt.Errorf(
					"security nat %s pool %q address range %s; range endpoints must be "+
						"bare IPs or host prefixes (/32 for IPv4, /128 for IPv6) of the "+
						"same family with low <= high",
					kind, name, pool.InvalidAddressRanges[0])
			}
		}
		return nil
	}
	if err := check("source", cfg.Security.NAT.SourcePools); err != nil {
		return err
	}
	if dst := cfg.Security.NAT.Destination; dst != nil {
		return check("destination", dst.Pools)
	}
	return nil
}
