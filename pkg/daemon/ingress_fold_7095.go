package daemon

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// ingress_fold_7095.go — #7095: the daemon side of the cluster-stable ingress
// identity that rides the HA session-sync wire.
//
// pkg/cluster deliberately holds no config, so the resolver is built here and
// injected. It is rebuilt on every config apply, which is also when the ifindex
// snapshot is taken, and again on every interface-link snapshot refresh
// (#15263: daemon_interface_link_refresh.go refreshIngressFoldClosures), so a
// member netdev recreated without a commit does not leave the closures naming
// its dead ifindex until the next commit.

// buildIngressFoldFn returns the resolver SessionSync stamps outgoing sessions
// with: a session's node-local {ifindex, vlan} to the fold of the interface's
// CLUSTER-STABLE name.
//
// Returns nil when there is nothing to resolve with, and nil is a supported
// value — SessionSync stamps 0, the unknown sentinel, which is what a legacy
// peer sends anyway. The failure mode of this whole path is degradation to the
// #4792 zone approximation, never a wrong interface name.
//
// THE IFINDEX SNAPSHOT IS TAKEN ONCE PER APPLY (and per link refresh,
// #15263), not per session: the send path walks every session in a bulk sync,
// and a netlink round trip each would put a syscall on that loop. A NIC that
// appears after this snapshot folds to 0 until the next commit or link
// refresh — it degrades, it does not lie. (A RECYCLED ifindex is the
// one case that could name the wrong device; that is #6987, which predates this
// change and is tracked separately for the local display path as well.)
func buildIngressFoldResolver(cfg *config.Config) func(uint32) (uint32, uint16, bool) {
	if cfg == nil {
		return nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	return buildIngressFoldResolverWithIfaces(cfg, ifaces)
}

// buildIngressFoldResolverWithIfaces is the testable core of
// buildIngressFoldResolver: the same pre-fold over an injected interface
// list, so tuple cells drive it without host netdevs. Production passes the
// once-per-apply snapshot above; behavior is identical.
func buildIngressFoldResolverWithIfaces(cfg *config.Config, ifaces []net.Interface) func(uint32) (uint32, uint16, bool) {
	indexByLinuxName := make(map[string]uint32, len(ifaces))
	for _, ifc := range ifaces {
		if ifc.Index > 0 {
			indexByLinuxName[ifc.Name] = uint32(ifc.Index)
		}
	}
	// Exact declared spellings, for the D25 short-circuit below. Resolved
	// names ARE declared spellings (the enumeration emits config names and
	// LocalIfaceForStableID resolves reth to the configured member), so an
	// exact hit means "this name is an interface", not a unit ref.
	declared := make(map[string]struct{}, len(cfg.Interfaces.Interfaces))
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		declared[name] = struct{}{}
	}
	// Pre-fold this node's own stable names once. The reverse direction runs per
	// imported session, and a bulk sync imports the peer's whole table.
	type local struct {
		ifindex uint32
		vlan    uint16
	}
	byFold := make(map[uint32]local)
	ambiguous := make(map[uint32]struct{})
	for _, stable := range cfg.ClusterStableIfaceNames() {
		fold := config.StableIfaceID(stable)
		if fold == 0 {
			continue
		}
		localName, ok := cfg.LocalIfaceForStableID(fold)
		if !ok {
			// LocalIfaceForStableID already refuses a collision; record it so a
			// later lookup does not silently take the other name's device.
			ambiguous[fold] = struct{}{}
			continue
		}
		base, vlan := localName, uint16(0)
		// #9821 D25: an exact-declared resolved name installs WHOLE with
		// vlan 0 — NO split. `p.0` installs its own device; the enum's
		// `p.0.100` candidate (undeclared) still splits to parent+vlan,
		// matching undotted handling; truncated legacy folds in
		// mixed-version flight take the unchanged path below.
		if _, isDeclared := declared[localName]; !isDeclared {
			if i := strings.LastIndexByte(localName, '.'); i >= 0 {
				if v, err := strconv.ParseUint(localName[i+1:], 10, 16); err == nil {
					base, vlan = localName[:i], uint16(v)
				}
			}
		}
		idx, ok := indexByLinuxName[config.LinuxIfName(base)]
		if !ok || idx == 0 {
			// This node does not currently have the device. Not an error: the
			// peer may be ahead of us, and the session degrades to the zone.
			continue
		}
		byFold[fold] = local{ifindex: idx, vlan: vlan}
	}
	return func(fold uint32) (uint32, uint16, bool) {
		if fold == 0 {
			return 0, 0, false
		}
		if _, bad := ambiguous[fold]; bad {
			return 0, 0, false
		}
		l, ok := byFold[fold]
		if !ok {
			return 0, 0, false
		}
		return l.ifindex, l.vlan, true
	}
}

func buildIngressFoldFn(cfg *config.Config) func(ifindex uint32, vlan uint16) uint32 {
	if cfg == nil {
		return nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	return buildIngressFoldFnWithIfaces(cfg, ifaces)
}

func buildIngressFoldFnWithIfaces(cfg *config.Config, ifaces []net.Interface) func(ifindex uint32, vlan uint16) uint32 {
	if cfg == nil {
		return nil
	}
	return ingressFoldFromNames(cfg, ingressFoldNameTable(ifaces))
}

// ingressFoldFromNames is the fold closure over one ifindex->name table. The
// #18374 ownership digest hashes that same table (ingressFoldDigest), so this
// closure must capture nothing else but cfg.
func ingressFoldFromNames(cfg *config.Config, nameByIndex map[uint32]string) func(ifindex uint32, vlan uint16) uint32 {
	if cfg == nil {
		return nil
	}
	// Pre-fold the names this config can produce so the send path does no
	// hashing per session — a bulk sync walks the whole table.
	return func(ifindex uint32, vlan uint16) uint32 {
		if ifindex == 0 {
			return 0
		}
		name := nameByIndex[ifindex]
		if name == "" {
			return 0
		}
		return config.StableIfaceID(cfg.ClusterStableIfaceName(name, vlan))
	}
}

// buildNatScopeFoldFnWithIfaces folds a #15176 NAT-scope ifindex the way the
// ingress fold folds a packet identity: as (parent physical, VLAN)
// (#16826). NatScopeIfindex names the LOGICAL unit — a kernel VLAN child
// (`ge-0-0-2.80`), or, for a bondless RETH unit with no child netdev, the
// synthetic logical-only ifindex the snapshot builder mints — so it is
// not a key into the kernel ifindex table and the generic
// {ifindex, vlan} folder truncated it to the parent (`reth0`).
//
// The (parent, VLAN) pair is derived from the config, keyed by the
// logical ifindex each shape carries, mirroring how the snapshot builder
// assigns it: a unit whose resolved Linux netdev exists (a secure-tunnel
// binding, TunnelNameMap entry, or VLAN child) keys on that netdev's kernel
// ifindex; a parent-bound RETH VLAN unit with no resolved child device keys
// on the synthetic ifindex allocated from the same sorted shared used-set as
// the snapshot builder; anything else (an untagged unit, a plain interface)
// keys on its own ifindex and folds with vlan 0 as before. An ifindex no
// derivation names folds to 0 — the unknown sentinel — so the peer keeps
// the #15176 no-scope keep rather than judging against a guessed parent
// scope. Captured once per apply (and rebuilt on the link refresh),
// matching buildIngressFoldFn's snapshot discipline; since #18374 both are
// built from the SAME interface table read (zoneOwnershipFromIfaces).
func buildNatScopeFoldFnWithIfaces(cfg *config.Config, ifaces []net.Interface) func(ifindex int32) uint32 {
	if cfg == nil {
		return nil
	}
	fold := buildIngressFoldFnWithIfaces(cfg, ifaces)
	if fold == nil {
		return nil
	}
	if !snapshotHasRethVlanUnit(cfg) {
		return nil
	}
	indexByLinuxName := make(map[string]uint32, len(ifaces))
	for _, ifc := range ifaces {
		if ifc.Index > 0 {
			indexByLinuxName[ifc.Name] = uint32(ifc.Index)
		}
	}
	type parentVLAN struct {
		parent uint32
		vlan   uint16
	}
	byIfindex := make(map[int32]parentVLAN)
	for _, ifc := range ifaces {
		if ifc.Index > 0 {
			byIfindex[int32(ifc.Index)] = parentVLAN{uint32(ifc.Index), 0}
		}
	}
	usedSyntheticIfindexes := make(map[int]struct{})
	// snapshotLinuxName queries this mapping for each unit; build it once for
	// this closure rather than allocating a full map in the loop.
	tunnelNames := cfg.TunnelNameMap()
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
		unitNums := make([]int, 0, len(iface.Units))
		for unitNum := range iface.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := iface.Units[unitNum]
			if unit == nil || unit.VlanID <= 0 {
				continue
			}
			parentName := cfg.ResolveReth(name)
			parentLinux := config.LinuxIfName(parentName)
			parentIdx, ok := indexByLinuxName[parentLinux]
			if !ok || parentIdx == 0 {
				continue
			}
			// Resolve the unit's kernel netdev exactly as the snapshot
			// builder does (snapshotLinuxName): a secure-tunnel binding
			// wins, then a tunnel-device mapping, then the VLAN child
			// `<parent>.<vid>`. Probing only the VLAN child would mint a
			// phantom synthetic index for a tunnel-resident unit the
			// builder emitted at the tunnel device's ifindex.
			unitRef := name + "." + strconv.Itoa(unit.Number)
			childLinux := parentLinux + "." + strconv.Itoa(unit.VlanID)
			if dev, ok := cfg.SecureTunnelUnitNetdev(unitRef); ok {
				childLinux = dev
			} else if dev, ok := tunnelNames[unitRef]; ok && dev != "" {
				childLinux = dev
			}
			childIdx, hasChild := indexByLinuxName[childLinux]
			if hasChild && childIdx != 0 {
				byIfindex[int32(childIdx)] = parentVLAN{parentIdx, uint16(unit.VlanID)}
			}
			if strings.HasPrefix(name, "reth") &&
				parentLinux != config.LinuxIfName(name) &&
				!hasChild {
				// Match buildInterfaceSnapshots' sorted interface/unit order
				// and mint only when it would emit a logical-only row
				// (parent present, VLAN child absent). The shared set matters:
				// independently probing each unit loses the builder's
				// collision displacement and can name another unit's NAT scope.
				unitName := name + "." + strconv.Itoa(unitNum)
				if syn := dpuserspace.SyntheticLogicalIfindexForUnit(unitName, unit.VlanID, usedSyntheticIfindexes); syn > 0 {
					byIfindex[int32(syn)] = parentVLAN{parentIdx, uint16(unit.VlanID)}
				}
			}
		}
	}
	return func(ifindex int32) uint32 {
		pv, ok := byIfindex[ifindex]
		if !ok {
			return 0
		}
		return fold(pv.parent, pv.vlan)
	}
}

// snapshotHasRethVlanUnit reports whether the config declares a tagged
// RETH unit — the only shape whose logical unit can differ from its
// parent. buildNatScopeFoldFnWithIfaces engages (returns non-nil) only then, so a
// config with no such unit keeps the legacy vlan-0 fold bit-identically
// instead of newly resolving (or dropping) scopes it folded before.
func snapshotHasRethVlanUnit(cfg *config.Config) bool {
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil || !strings.HasPrefix(name, "reth") {
			continue
		}
		for _, unit := range ifc.Units {
			if unit != nil && unit.VlanID > 0 {
				return true
			}
		}
	}
	return false
}
