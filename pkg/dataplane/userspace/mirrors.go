package userspace

import (
	"log/slog"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// buildMirrorConfigSnapshots resolves forwarding-options port-mirroring into
// the per-ingress mirror table. The table contract is one output per ingress
// ifindex, so a duplicate ingress ifindex (the same physical interface used as
// an ingress source by more than one instance) or a negative sampling rate is
// a SCOPE-DROP: the offending entry is skipped with a specific warning and the
// remaining valid entries are still published (#3972). One typo must never
// silently disable ALL mirroring.
//
// config.compilePortMirroring already HARD-REJECTS these cases at commit time,
// so this scope-drop is defense-in-depth for a config that reaches the
// snapshot builder without passing the commit gate (e.g. a stale on-disk
// config written by an older build). It replaces the pre-#3972
// whole-table-fail-closed-on-warn behavior that dropped every valid mirror
// session on a single bad entry.
// MirrorExclusion records ONE port-mirroring entry the builder refused to
// install, and why (#7357 §2).
//
// WHY A RECORD RATHER THAN A PREDICATE. Every other #6534 family is closed by
// a shared config predicate both the builder and the renderers call, so they
// cannot disagree. These three drops cannot be: they depend on the runtime
// ifindex table, which a config-only renderer has no access to.
//
// The obvious alternative — hand the renderer the resolved ifindex map so it
// can re-derive — answers a DIFFERENT QUESTION from the one the operator
// asked. `show forwarding-options port-mirroring` asks what IS installed. A
// re-derivation against a live interface table reports what WOULD be installed
// if the builder ran again now, and an ifindex is a runtime identity that
// moves across a netdev recreate. When those two disagree the truthful answer
// is still the applied one, and the disagreement means a MISSED REBUILD — a
// bug in a different component that a re-deriving renderer would silently
// paper over. That is this issue's own failure mode reintroduced one layer up.
//
// So the builder records the verdict it actually reached, at apply time, and
// the renderer prints that.
//
// Input is empty for an instance-level drop and set for an input-level one.
// The granularity is not cosmetic: an instance whose output resolves but whose
// second input is claimed is PARTIALLY installed, and marking the whole
// instance NOT INSTALLED would lie in the other direction — the same defect
// with the sign flipped.
type MirrorExclusion struct {
	Instance string `json:"instance"`
	Input    string `json:"input,omitempty"`
	Reason   string `json:"reason"`
}

func buildMirrorConfigSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot) ([]MirrorConfigSnapshot, []MirrorExclusion) {
	if cfg == nil || cfg.ForwardingOptions.PortMirroring == nil || len(cfg.ForwardingOptions.PortMirroring.Instances) == 0 {
		return nil, nil
	}
	ifindexByName := make(map[string]int, len(interfaces))
	// #15113: unit identity of the row a name resolves to. A unit row
	// (IsUnit) is unit-scoped with its VLANID; a base row is the bare
	// physical input. Unit 0 (VLANID 0) shares the base ifindex, so the
	// ifindex alone cannot distinguish `ge-0/0/1.0` from `ge-0/0/1`.
	type mirrorIngressScope struct {
		vlanID     int
		unitScoped bool
	}
	scopeByName := make(map[string]mirrorIngressScope, len(interfaces))
	for _, iface := range interfaces {
		if iface.Ifindex > 0 {
			ifindexByName[iface.Name] = iface.Ifindex
			scopeByName[iface.Name] = mirrorIngressScope{vlanID: iface.VLANID, unitScoped: iface.IsUnit}
			if iface.LinuxName != "" {
				ifindexByName[iface.LinuxName] = iface.Ifindex
				scopeByName[iface.LinuxName] = mirrorIngressScope{vlanID: iface.VLANID, unitScoped: iface.IsUnit}
				// #15651: a unit row's LinuxName is the kernel device
				// (unit 0 collapses onto the parent; a VLAN unit is
				// `<parent>.<vid>`), so neither Name nor LinuxName ever
				// equals the Linux unit spelling an operator can write
				// (`ge-0-0-0.0`). Index that spelling too, derived from
				// the row's configured name, so it resolves with the
				// row's own scope instead of disappearing.
				if iface.IsUnit {
					if linuxUnit := config.LinuxIfName(iface.Name); linuxUnit != iface.Name && linuxUnit != iface.LinuxName {
						ifindexByName[linuxUnit] = iface.Ifindex
						scopeByName[linuxUnit] = mirrorIngressScope{vlanID: iface.VLANID, unitScoped: iface.IsUnit}
					}
				}
			}
		}
	}

	instanceNames := make([]string, 0, len(cfg.ForwardingOptions.PortMirroring.Instances))
	for name := range cfg.ForwardingOptions.PortMirroring.Instances {
		instanceNames = append(instanceNames, name)
	}
	sort.Strings(instanceNames)

	// #15113: duplicate ownership is per (ifindex, vlan, unit-scoped), so
	// a bare physical input and a unit-0 input on the same ifindex are
	// distinct rows (the Rust resolver prefers the unit row for VID 0).
	type mirrorIngressKey struct {
		ifindex    int
		vlanID     int
		unitScoped bool
	}
	seenIngress := make(map[mirrorIngressKey]string)
	out := make([]MirrorConfigSnapshot, 0)
	var excluded []MirrorExclusion
	for _, name := range instanceNames {
		inst := cfg.ForwardingOptions.PortMirroring.Instances[name]
		if inst == nil {
			continue
		}
		// Config-decidable drops: no output interface, or a negative rate that
		// would wrap in uint32(inst.InputRate) below. Drop only this instance;
		// the commit gate (validateSamplingInputRateStrict) rejects it up
		// front, so this is the lenient load / peer-sync backstop.
		//
		// #6534: the verdict is config.PortMirroringInstanceExcludedReason so
		// this builder and BOTH port-mirroring show surfaces cannot disagree
		// about which instances are armed. The two interface-resolution drops
		// below are NOT in that predicate — they depend on the runtime ifindex
		// table, which a config-only renderer cannot reach.
		if reason := config.PortMirroringInstanceExcludedReason(inst); reason != "" {
			slog.Warn("port-mirroring: skipping instance (fail-closed)",
				"name", name, "reason", reason, "rate", inst.InputRate, "output", inst.Output)
			// Not recorded here: the renderers already annotate this one from
			// the shared config predicate, and recording it too would make the
			// same instance print NOT INSTALLED twice.
			continue
		}
		outputIfindex := ifindexByName[inst.Output]
		if outputIfindex <= 0 {
			outputIfindex = ifindexByName[config.LinuxIfName(inst.Output)]
		}
		if outputIfindex <= 0 {
			// #15651: Junos/VLAN/RETH/tunnel spellings (`ge-0/0/0.0`,
			// `ge-0/0/3.1` on a VLAN unit, `reth0.0`) only reduce to the
			// kernel device through the config resolver.
			outputIfindex = ifindexByName[cfg.ResolveKernelIfName(inst.Output)]
		}
		if outputIfindex <= 0 {
			slog.Warn("port-mirroring output interface not found",
				"name", name, "interface", inst.Output)
			excluded = append(excluded, MirrorExclusion{
				Instance: name,
				Reason:   "output interface " + inst.Output + " has no ifindex",
			})
			continue
		}

		for _, input := range inst.Input {
			ingressIfindex := ifindexByName[input]
			scope, scopeOK := scopeByName[input]
			if ingressIfindex <= 0 {
				ingressIfindex = ifindexByName[config.LinuxIfName(input)]
				scope, scopeOK = scopeByName[config.LinuxIfName(input)]
			}
			if ingressIfindex <= 0 {
				// #15651: see the output arm above — resolve through
				// the config so unit/RETH/VLAN/tunnel spellings reach
				// the row (and its scope) the raw LinuxIfName missed.
				resolved := cfg.ResolveKernelIfName(input)
				ingressIfindex = ifindexByName[resolved]
				scope, scopeOK = scopeByName[resolved]
			}
			if ingressIfindex <= 0 {
				slog.Warn("port-mirroring input interface not found",
					"name", name, "interface", input)
				excluded = append(excluded, MirrorExclusion{
					Instance: name,
					Input:    input,
					Reason:   "input interface " + input + " has no ifindex",
				})
				continue
			}
			if !scopeOK {
				scope = mirrorIngressScope{}
			}
			key := mirrorIngressKey{ifindex: ingressIfindex, vlanID: scope.vlanID, unitScoped: scope.unitScoped}
			if previous, ok := seenIngress[key]; ok {
				slog.Warn("port-mirroring: skipping duplicate ingress interface (one output per ingress interface)",
					"name", name, "interface", input, "ifindex", ingressIfindex, "owner", previous)
				excluded = append(excluded, MirrorExclusion{
					Instance: name,
					Input:    input,
					Reason:   "ingress interface " + input + " already mirrored by instance " + previous,
				})
				continue
			}
			seenIngress[key] = name
			out = append(out, MirrorConfigSnapshot{
				IngressIfindex: ingressIfindex,
				OutputIfindex:  outputIfindex,
				Rate:           uint32(inst.InputRate),
				IngressVLANID:  scope.vlanID,
				UnitScoped:     scope.unitScoped,
			})
		}
	}
	return out, excluded
}
