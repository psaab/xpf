package userspace

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// neighborsEqual returns true if two neighbor snapshot slices have identical content.
func neighborsEqual(a, b []NeighborSnapshot) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// neighborsEqualForwarding returns true if two snapshots are
// equivalent for forwarding decisions: same publishable-key set,
// same MAC for each shared key. Raw NUD state (REACHABLE vs STALE)
// is NOT compared because both are usable for forwarding and aging
// churn shouldn't trigger republish.
//
// #1197: prevents the 60s safety reconciliation tick (and any
// other regeneration trigger) from publishing on harmless
// REACHABLE↔STALE transitions, while still detecting MAC change
// or transition to unusable state (which removes a key from the
// publishable set).
func neighborsEqualForwarding(a, b []NeighborSnapshot) bool {
	type keyMac struct {
		ifindex int
		ip, mac string
	}
	publishable := func(ns []NeighborSnapshot) map[keyMac]struct{} {
		out := make(map[keyMac]struct{}, len(ns))
		for _, n := range ns {
			if neighborSnapshotPublishable(n) {
				out[keyMac{n.Ifindex, n.IP, n.MAC}] = struct{}{}
			}
		}
		return out
	}
	am, bm := publishable(a), publishable(b)
	if len(am) != len(bm) {
		return false
	}
	for k := range am {
		if _, ok := bm[k]; !ok {
			return false
		}
	}
	return true
}

// neighborSnapshotPublishable returns true for a structurally valid kernel
// neighbor row whose state is not known-unusable, so the Go manager can avoid
// publishing malformed or failed entries. This context-free gate cannot decide
// whether an IP is the directed broadcast of a configured connected prefix.
// Rust applies its state allowlist and the config-aware, egress-specific #11033
// broadcast gate when importing or resolving neighbors; a Go-publishable row is not
// necessarily usable for forwarding.
//
// Keep the generic shape/state checks aligned with Rust's
// `neighbor_state_usable` contract when either side changes.
func neighborSnapshotPublishable(n NeighborSnapshot) bool {
	if n.Ifindex <= 0 {
		return false
	}
	if net.ParseIP(n.IP) == nil {
		return false
	}
	if _, err := net.ParseMAC(n.MAC); err != nil {
		return false
	}
	lower := strings.ToLower(n.State)
	if strings.Contains(lower, "failed") ||
		strings.Contains(lower, "incomplete") ||
		strings.Contains(lower, "noarp") {
		return false
	}
	if lower == "none" {
		return false
	}
	return true
}

// MonitoredInterfaceLinkIndexes returns the set of kernel link
// indexes that buildNeighborSnapshots iterates over. Exported so
// the daemon's neighbor listener can filter incoming netlink
// events to exactly the same keyspace — guaranteeing no drift
// between snapshot publish and listener filter.
//
// #1197: previously the daemon's listener filter was inferred
// independently, which risks publishing snapshot entries the
// listener can't see updates for.
func MonitoredInterfaceLinkIndexes(cfg *config.Config) map[int]struct{} {
	out := make(map[int]struct{})
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return out
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		linuxNames := []string{snapshotLinuxName(cfg, name, iface, nil)}
		if len(iface.Units) > 0 {
			unitNums := make([]int, 0, len(iface.Units))
			for unitNum := range iface.Units {
				unitNums = append(unitNums, unitNum)
			}
			sort.Ints(unitNums)
			for _, unitNum := range unitNums {
				unit := iface.Units[unitNum]
				if unit == nil {
					continue
				}
				linuxNames = append(linuxNames, snapshotLinuxName(cfg, name, iface, unit))
			}
		}
		for _, linuxName := range linuxNames {
			link, err := netlink.LinkByName(linuxName)
			if err != nil || link == nil {
				continue
			}
			out[link.Attrs().Index] = struct{}{}
		}
	}
	return out
}

func buildNeighborSnapshots(cfg *config.Config) []NeighborSnapshot {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]NeighborSnapshot, 0)
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		linuxNames := []string{snapshotLinuxName(cfg, name, iface, nil)}
		if len(iface.Units) > 0 {
			unitNums := make([]int, 0, len(iface.Units))
			for unitNum := range iface.Units {
				unitNums = append(unitNums, unitNum)
			}
			sort.Ints(unitNums)
			for _, unitNum := range unitNums {
				unit := iface.Units[unitNum]
				if unit == nil {
					continue
				}
				linuxNames = append(linuxNames, snapshotLinuxName(cfg, name, iface, unit))
			}
		}
		for _, linuxName := range linuxNames {
			link, err := netlink.LinkByName(linuxName)
			if err != nil || link == nil {
				continue
			}
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				neighs, err := netlink.NeighList(link.Attrs().Index, family)
				if err != nil {
					continue
				}
				for _, neigh := range neighs {
					if neigh.IP == nil {
						continue
					}
					key := fmt.Sprintf("%d/%s", link.Attrs().Index, neigh.IP.String())
					if seen[key] {
						continue
					}
					seen[key] = true
					fam := "inet"
					if family == netlink.FAMILY_V6 {
						fam = "inet6"
					}
					mac := ""
					if neigh.HardwareAddr != nil {
						mac = neigh.HardwareAddr.String()
					}
					out = append(out, NeighborSnapshot{
						Interface: linuxName,
						Ifindex:   link.Attrs().Index,
						Family:    fam,
						IP:        neigh.IP.String(),
						MAC:       mac,
						State:     neighborStateString(neigh.State),
						Router:    neigh.Flags&netlink.NTF_ROUTER != 0,
						LinkLocal: neigh.IP.IsLinkLocalUnicast(),
					})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].IP < out[j].IP
	})
	return out
}

func neighborStateString(state int) string {
	parts := make([]string, 0, 4)
	if state&netlink.NUD_PERMANENT != 0 {
		parts = append(parts, "permanent")
	}
	if state&netlink.NUD_REACHABLE != 0 {
		parts = append(parts, "reachable")
	}
	if state&netlink.NUD_STALE != 0 {
		parts = append(parts, "stale")
	}
	if state&netlink.NUD_DELAY != 0 {
		parts = append(parts, "delay")
	}
	if state&netlink.NUD_PROBE != 0 {
		parts = append(parts, "probe")
	}
	if state&netlink.NUD_FAILED != 0 {
		parts = append(parts, "failed")
	}
	if state&netlink.NUD_NOARP != 0 {
		parts = append(parts, "noarp")
	}
	if state&netlink.NUD_INCOMPLETE != 0 {
		parts = append(parts, "incomplete")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}
