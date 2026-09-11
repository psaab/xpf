package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// #9727: the userspace dataplane receives into fixed-size UMEM frames and binds
// its AF_XDP sockets without multi-buffer (XDP_USE_SG) support, so a frame
// larger than one UMEM frame cannot reach a worker. In copy mode the kernel
// drops it and counts it in the XSK rx_dropped counter (surfaced as
// kernel_rx_dropped); a zero-copy driver may refuse the XSK setup instead, and
// the #7191 arm then fails closed. The interface `mtu` leaf accepts any value,
// so a jumbo MTU on a bound interface committed clean and turned into drops or
// a refused bind with nothing at commit saying why.

const (
	// userspaceUMEMFrameSize and userspaceUMEMHeadroom mirror UMEM_FRAME_SIZE
	// and UMEM_HEADROOM in userspace-dp/src/afxdp/mod.rs;
	// TestUserspaceUMEMConstantsMatchTheHelper9727 binds them.
	userspaceUMEMFrameSize = 4096
	userspaceUMEMHeadroom  = 256
	// userspaceRxMTUBudget is the largest MTU whose frame fits one UMEM frame:
	// the frame minus the XDP headroom, a 14-byte Ethernet header and one 4-byte
	// 802.1Q tag (FCS is stripped before XDP).
	userspaceRxMTUBudget = userspaceUMEMFrameSize - userspaceUMEMHeadroom - 14 - 4
)

// appendUserspaceRxMTUAdvisoryLocked warns once per interface the userspace
// dataplane binds whose effective MTU exceeds userspaceRxMTUBudget.
//
// "Binds" mirrors the dataplane's own rule (userspaceSkipsIngressInterface and
// netdevExclusionClasses in pkg/dataplane/userspace), which pkg/config cannot
// import:
//   - only interfaces referenced by a security zone;
//   - not the mgmt or control zones;
//   - not tunnels, fxp*, em*, fab* or lo0;
//   - not local fabric members.
//
// A WARNING, not an error. Commit cannot tell a copy-mode binding (drops
// counted) from a zero-copy one (a refused bind), and a jumbo MTU remains
// correct for the kernel-forwarded traffic of an interface.
// opts.suppressContestedTrunkZoneAdvisory silences it on the tolerant boot and
// peer-sync paths, for the reason given at appendContestedTrunkZoneAdvisoryLocked.
func appendUserspaceRxMTUAdvisoryLocked(cfg *Config, opts compileOpts) {
	if cfg == nil || opts.suppressContestedTrunkZoneAdvisory {
		return
	}
	over := userspaceRxMTUOverBudget(cfg)
	bases := make([]string, 0, len(over))
	for base := range over {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	for _, base := range bases {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
			"interface %s has MTU %d, above the userspace dataplane's single-frame receive "+
				"budget of %d bytes (a %d-byte UMEM frame minus %d bytes of headroom and the "+
				"Ethernet/VLAN header; AF_XDP is bound without multi-buffer support): frames "+
				"larger than the budget cannot reach a worker. They are dropped and counted in "+
				"kernel_rx_dropped, or a zero-copy driver refuses the AF_XDP bind (#9727).",
			base, over[base], userspaceRxMTUBudget, userspaceUMEMFrameSize, userspaceUMEMHeadroom))
	}
}

// userspaceRxMTUOverBudget returns base interface name -> the largest effective
// MTU above the budget among its zoned, dataplane-bound references.
func userspaceRxMTUOverBudget(cfg *Config) map[string]int {
	out := map[string]int{}
	if cfg.Security.Zones == nil || cfg.Interfaces.Interfaces == nil {
		return out
	}
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil || zoneName == "mgmt" || zoneName == "control" {
			continue
		}
		for _, ref := range zone.Interfaces {
			base, unitText, _ := strings.Cut(ref, ".")
			if strings.HasPrefix(base, "fxp") || strings.HasPrefix(base, "em") ||
				strings.HasPrefix(base, "fab") || base == "lo0" {
				continue
			}
			ifc := cfg.Interfaces.Interfaces[base]
			if ifc == nil || ifc.Tunnel != nil || ifc.LocalFabricMember != "" {
				continue
			}
			mtu := ifc.MTU
			if unitNum, err := strconv.Atoi(unitText); err == nil || unitText == "" {
				if unit := ifc.Units[unitNum]; unit != nil {
					if unit.Tunnel != nil {
						continue
					}
					if unit.MTU > 0 {
						mtu = unit.MTU
					}
				}
			}
			if mtu > userspaceRxMTUBudget && mtu > out[base] {
				out[base] = mtu
			}
		}
	}
	return out
}
