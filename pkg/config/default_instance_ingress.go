package config

import (
	"fmt"
	"sort"
)

// DefaultInstanceIngressIfaces returns the sorted, de-duplicated kernel ifnames
// of every configured interface unit that is NOT assigned to a routing
// instance — i.e. the ingress interfaces of the DEFAULT routing instance.
//
// This is the single shared (#9810) implementation of the #9420 scoping set.
// It lives in pkg/config rather than pkg/routing so the strict commit gate
// (compiler_validate_strict_routing_rulewindows.go) and the shared FIB/show
// verdict (static_route_exclusion_reason.go) can count the SAME set the
// applier installs per: since #9420 each next-table leak costs one ip-rule
// slot per ingress interface, and the gate/verdict counting one slot per leak
// is the SYN-WIN-01 kernel/FIB split. pkg/routing's same-named function
// delegates here, so the three consumers cannot drift. pkg/config cannot
// import pkg/routing (import cycle), which is why the shared copy lives on
// this side.
//
// Loopback is deliberately EXCLUDED (SYN-LO0-02): an `iif lo` rule matches
// locally generated traffic including sockets bound to ANOTHER VRF (the
// #9420 cross-VRF hijack), and the configured `lo0` idiom resolves to the
// nonexistent `lo0`, whose rules install detached and only inflate N.
func DefaultInstanceIngressIfaces(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	claimed := make(map[string]struct{})
	claimedBare := make(map[string]struct{})
	// #9810: hoist the tunnel-name map once — ResolveKernelIfName rebuilds it
	// per call, and this resolver now runs per commit (gate), per FIB build
	// and per show render, which would triple the #8854/#8862 quadratic.
	tunMap := tunnelNameMapFn(cfg)
	for _, inst := range cfg.RoutingInstances {
		if inst == nil {
			continue
		}
		for _, ref := range inst.Interfaces {
			s := cfg.SplitInterfaceUnitRef(ref)
			claimed[ref] = struct{}{}
			// A bare claim owns the whole stanza. Keep its raw linux
			// spelling in a separate partition so a dash/slash alias skips
			// the declared stanza without changing unit-claim rules. The
			// resolved name remains in claimed below; it can differ for reth.
			if !s.HasUnit {
				claimedBare[LinuxIfName(s.Base)] = struct{}{}
			}
			// An instance may claim the base interface ("ge-0/0/0") or a unit
			// ref ("ge-0/0/0.0"). Record the resolved kernel name too so a
			// claim written in either spelling excludes the same device.
			if k := cfg.resolveKernelIfNameWith(ref, tunMap); k != "" {
				claimed[k] = struct{}{}
			}
		}
	}

	seen := make(map[string]struct{})
	var out []string
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		// #9810 SYN-LO0-02: skip the whole loopback stanza — every unit of
		// it, not just unit 0 (`lo0.5` resolves detached like `lo0` does).
		if IsLoopbackIngress(ifc.Name) {
			continue
		}
		// #9815: claimedBare is the bare-origin partition layered on
		// #9810's resolved claim set. Unit claims stay per-device below.
		if _, taken := claimed[ifc.Name]; taken {
			continue
		}
		if _, taken := claimedBare[LinuxIfName(ifc.Name)]; taken {
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			ref := fmt.Sprintf("%s.%d", ifc.Name, unit.Number)
			if _, taken := claimed[ref]; taken {
				continue
			}
			iif := cfg.resolveKernelIfNameWith(ref, tunMap)
			if iif == "" {
				continue
			}
			// Belt: no matter how the stanza was spelled, a resolved
			// loopback ingress (`lo`, `lo0`, `lo0.5`) never becomes an `iif`
			// scope — `iif lo` is the live #9420 hijack, `iif lo0*` detached.
			if IsLoopbackIngress(iif) {
				continue
			}
			if _, taken := claimed[iif]; taken {
				continue
			}
			if _, dup := seen[iif]; dup {
				continue
			}
			seen[iif] = struct{}{}
			out = append(out, iif)
		}
	}
	sort.Strings(out)
	return out
}
