package grpcapi

import (
	"sort"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/monitoriface"
)

// monitorResolveToKernel converts a config-level interface name to its kernel
// name against a SPECIFIC config: "ge-0/0/0" → "ge-0-0-0", "reth0" → the local
// physical member's kernel name.
//
// It takes the config as a parameter rather than closing over one so the caller
// decides which snapshot it is resolving against. That is the whole distinction
// #9144 turns on.
func monitorResolveToKernel(cfg *config.Config, cfgName string) string {
	if cfg == nil {
		return config.LinuxIfName(cfgName)
	}
	return config.LinuxIfName(cfg.ResolveReth(cfgName))
}

// monitorSummaryInterfaces returns the summary-mode display names and the kernel
// interface backing each, derived from the CURRENT active config on every call.
//
// #9144: MonitorInterface took `cfg := s.store.ActiveConfig()` once at stream
// open and the 1s tick loop kept using it for the life of the stream. The
// interface SET and the COUNTERS were never stale — TrafficSummaryInterfaces
// calls ListTrafficInterfaces() first, a fresh netlink walk every tick, and reads
// counters by live kernel name. What was stale is the config-derived DISPLAY
// NAME: applyConfiguredSummaryChoices maps configured names onto live kernel
// devices, so a commit that re-points an alias (a device-map edit, a RETH member
// change) left live counters rendered under a name that now belongs to something
// else. A wrong label on real data — worse than a missing row, because nothing
// about it looks wrong.
//
// Measured, driving the real store through a real commit:
//
//	BEFORE commit:                       kernel lo is displayed as "reth0"
//	AFTER commit, PINNED snapshot:       kernel lo is displayed as "reth0"
//	AFTER commit, RE-READ:               kernel lo is displayed as "reth9"
//
// WHY THIS IS NOT THE #9051 SHAPE, and why the interceptor remedy does not
// transplant. #9051 fixed a long-lived stream holding state captured at open by
// re-checking at the INTERCEPTOR rather than in each handler's loop, because
// putting it in the loops covers the streams that exist and silently omits the
// next one. That works there because the property is UNIFORM — "is this
// principal still authorized for this method?" is computed from the peer
// identity and the method name, both of which the interceptor already holds, and
// the enforcement action is uniform too: cancel the stream.
//
// A config snapshot is the opposite on both counts. The derivation is
// handler-SPECIFIC (this handler alone derives a kernel-name resolver, a RETH
// predicate, an RG lookup and a display-name mapping from cfg; an interceptor
// cannot re-derive closures that live inside a handler body), and there is no
// uniform enforcement action — cancelling an operator's `monitor interface`
// because someone committed is plainly wrong. So the fix belongs in the handler,
// and the "silently omits the next one" concern is answered by scope instead:
// MonitorInterface is the only stream that renders live data under a
// config-derived alias. MonitorPacketDrop also reads the config at open, but
// only to VALIDATE the request's zone/interface filters and resolve the
// requested alias set — pinning the interpretation of what the operator asked
// for is correct there, and it renders no config-derived label.
//
// #10838: single-interface monitoring re-resolves the requested display name
// to its current kernel device each tick. ResetOnDeviceChange drops the
// per-device prev/baseline snapshots and the frame carries a persistent note
// when the member changes. RG ownership is monitored separately: since an
// already-open stream cannot migrate to the new primary, a local/peer ownership
// transition resets its baselines and annotates the local counters as potentially
// stale. The stream-entry uses below stay pinned:
// isRethName / rethRG feed the serve-local vs proxy-to-peer dispatch, which is
// settled before the loop and cannot switch the stream's peer mid-flight.
//
// openCfg is the snapshot the stream opened with and is used ONLY when the
// re-read returns nil (a store transiently without an active config): the stream
// degrades to its previous frame rather than erroring out, since a monitor
// stream that dies on a config blip is a worse failure than one stale label.
func (s *Server) monitorSummaryInterfaces(openCfg *config.Config) ([]string, map[string]string) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		cfg = openCfg
	}
	if cfg == nil {
		return nil, nil
	}
	if names, kernelNames := monitoriface.TrafficSummaryInterfaces(cfg); len(names) > 0 {
		return names, kernelNames
	}

	// Fallback: no live traffic interfaces at all (netlink returned nothing).
	// Effectively unreachable on a running box, which always has at least `lo`.
	if cfg.Interfaces.Interfaces == nil {
		return nil, nil
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	kernelNames := make(map[string]string, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
		kernelNames[name] = monitoriface.ResolvePhysicalParent(monitorResolveToKernel(cfg, name))
	}
	sort.Strings(names)
	return names, kernelNames
}
