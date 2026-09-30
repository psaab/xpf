package daemon

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
)

// frrProtocolInterfaceRefs11310 collects the interface operands whose FRR
// protocol stanza must be scoped to the interface's routing-instance owner.
// BGP peers are address-based and are deliberately not included.
func frrProtocolInterfaceRefs11310(protocols config.ProtocolsConfig) []string {
	var refs []string
	if protocols.OSPF != nil {
		for _, area := range protocols.OSPF.Areas {
			if area == nil {
				continue
			}
			for _, iface := range area.Interfaces {
				if iface != nil && iface.Name != "" {
					refs = append(refs, iface.Name)
				}
			}
		}
	}
	if protocols.OSPFv3 != nil {
		for _, area := range protocols.OSPFv3.Areas {
			if area == nil {
				continue
			}
			for _, iface := range area.Interfaces {
				if iface != nil && iface.Name != "" {
					refs = append(refs, iface.Name)
				}
			}
		}
	}
	if protocols.RIP != nil {
		for _, ref := range protocols.RIP.Interfaces {
			if ref != "" {
				refs = append(refs, ref)
			}
		}
		for _, ref := range protocols.RIP.Passive {
			if ref != "" {
				refs = append(refs, ref)
			}
		}
	}
	if protocols.ISIS != nil {
		for _, iface := range protocols.ISIS.Interfaces {
			if iface != nil && iface.Name != "" {
				refs = append(refs, iface.Name)
			}
		}
	}
	return refs
}

// filterFRRProtocolInterfaces11310 returns copies of the IGP protocol configs
// with interface operands removed unless the device belongs to the stanza's
// routing instance. The strict config gate reports new mismatches; this render
// belt keeps legacy/tolerantly-loaded configs from activating protocols in a
// different FRR instance. It never mutates the active compiled config.
func filterFRRProtocolInterfaces11310(
	protocols config.ProtocolsConfig,
	instance string,
	ownersByRef map[string]string,
) config.ProtocolsConfig {
	out := protocols
	out.OSPF = filterOSPFProtocolInterfaces11310(protocols.OSPF, "ospf", instance, ownersByRef)
	out.OSPFv3 = filterOSPFv3ProtocolInterfaces11310(protocols.OSPFv3, "ospf3", instance, ownersByRef)
	out.RIP = filterRIPProtocolInterfaces11310(protocols.RIP, instance, ownersByRef)
	out.ISIS = filterISISProtocolInterfaces11310(protocols.ISIS, instance, ownersByRef)
	return out
}

func filterOSPFProtocolInterfaces11310(src *config.OSPFConfig, proto, instance string, ownersByRef map[string]string) *config.OSPFConfig {
	if src == nil {
		return nil
	}
	out := *src
	out.Areas = make([]*config.OSPFArea, 0, len(src.Areas))
	for _, area := range src.Areas {
		if area == nil {
			out.Areas = append(out.Areas, nil)
			continue
		}
		areaCopy := *area
		areaCopy.Interfaces = make([]*config.OSPFInterface, 0, len(area.Interfaces))
		for _, iface := range area.Interfaces {
			if iface == nil || !keepFRRProtocolInterface11310(iface.Name, proto, instance, ownersByRef) {
				continue
			}
			ifaceCopy := *iface
			areaCopy.Interfaces = append(areaCopy.Interfaces, &ifaceCopy)
		}
		out.Areas = append(out.Areas, &areaCopy)
	}
	return &out
}

func filterOSPFv3ProtocolInterfaces11310(src *config.OSPFv3Config, proto, instance string, ownersByRef map[string]string) *config.OSPFv3Config {
	if src == nil {
		return nil
	}
	out := *src
	out.Areas = make([]*config.OSPFv3Area, 0, len(src.Areas))
	for _, area := range src.Areas {
		if area == nil {
			out.Areas = append(out.Areas, nil)
			continue
		}
		areaCopy := *area
		areaCopy.Interfaces = make([]*config.OSPFv3Interface, 0, len(area.Interfaces))
		for _, iface := range area.Interfaces {
			if iface == nil || !keepFRRProtocolInterface11310(iface.Name, proto, instance, ownersByRef) {
				continue
			}
			ifaceCopy := *iface
			areaCopy.Interfaces = append(areaCopy.Interfaces, &ifaceCopy)
		}
		out.Areas = append(out.Areas, &areaCopy)
	}
	return &out
}

func filterRIPProtocolInterfaces11310(src *config.RIPConfig, instance string, ownersByRef map[string]string) *config.RIPConfig {
	if src == nil {
		return nil
	}
	out := *src
	out.Interfaces = filterFRRProtocolInterfaceNames11310(src.Interfaces, "rip", instance, ownersByRef)
	out.Passive = filterFRRProtocolInterfaceNames11310(src.Passive, "rip", instance, ownersByRef)
	return &out
}

func filterISISProtocolInterfaces11310(src *config.ISISConfig, instance string, ownersByRef map[string]string) *config.ISISConfig {
	if src == nil {
		return nil
	}
	out := *src
	out.Interfaces = make([]*config.ISISInterface, 0, len(src.Interfaces))
	for _, iface := range src.Interfaces {
		if iface == nil || !keepFRRProtocolInterface11310(iface.Name, "isis", instance, ownersByRef) {
			continue
		}
		ifaceCopy := *iface
		out.Interfaces = append(out.Interfaces, &ifaceCopy)
	}
	return &out
}

func filterFRRProtocolInterfaceNames11310(refs []string, proto, instance string, ownersByRef map[string]string) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		if keepFRRProtocolInterface11310(ref, proto, instance, ownersByRef) {
			out = append(out, ref)
		}
	}
	return out
}

func keepFRRProtocolInterface11310(ref, proto, instance string, ownersByRef map[string]string) bool {
	// `all` is a literal unexpanded wildcard (warned by #9405), not a device
	// whose ownership can be resolved. Preserve its existing render behavior.
	if ref == "all" {
		return true
	}
	owner := ownersByRef[ref]
	if owner == instance {
		return true
	}
	scope := "global protocols"
	if instance != "" {
		scope = "routing-instances " + instance + " protocols"
	}
	slog.Warn("dropping FRR protocol interface outside routing-instance membership (#11310)",
		"scope", scope, "protocol", proto, "interface", ref, "owner", owner)
	return false
}
