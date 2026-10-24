package configstore

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// #16473: shipped lab configs claimed the same IPv4 on the shared
// 172.16.50.0/24 segment. The udp cluster's WAN RETH (.11,
// docs/ha-cluster-udp.conf) was also the standalone VM's NAT64 source
// pool (test/incus/xpf-test.conf nat64-pool), and the standalone
// proxy-ARPed .6, the legacy local cluster's WAN RETH
// (docs/ha-cluster.conf), which was also its nat64-snat-pool. Co-running
// stacks ARP-fight / mis-deliver NAT replies and confound HA/NAT
// measurements. The §3.3 registry in docs/incus-tcp-udp-plan.md listed
// only loss/tcp/udp, which is how .11 was allocated twice.
//
// This cell is the hermetic census the issue's acceptance asks for: it
// compiles every deployed lab config that can sit on the shared
// 172.16.50.0/24 or 172.16.80.0/24 segments and asserts that each
// address in those networks has exactly ONE owning stack. The only
// accepted overlap is the documented 172.16.80.7 leg (legacy-loss RETH
// and the loss userspace stack's own SNAT pool/proxy-ARP are the same
// stack; see §3.3).
//
// Grouping is by STACK, not file: docs/ha-cluster.conf and
// test/incus/xpf-cluster-fw{0,1}.conf are the same legacy local stack
// (fw{0,1} are its expanded per-node views), so intra-stack repetition
// (RETH on both nodes) is one owner. Any other cross-stack repetition
// is a COLLISION. Pool-only claims count as owners too: a source pool
// whose address another stack ARP-owns (interface or proxy-ARP) has
// its return traffic delivered to that stack even when the pool owner
// does not itself ARP.
//
// IPv6 is censused the same way (the shared 2001:559:8585:50::/64 and
// :80::/64): cross-stack claims there ND-fight exactly as v4 ARP-fights.
//
// RED on revert: restore 172.16.50.11 in xpf-test.conf's nat64-pool (or
// 172.16.50.6 in its proxy-arp / nat64-snat-pool) and the standalone
// subtests fail naming both claiming stacks.

type labStack struct {
	name  string
	files []string // repo-relative, compiled via CheckText
}

// labStacks16473 enumerates the shipped configs deployed onto the
// shared segments. xpf-internet-test.conf / xpf-vlan-test.conf carry no
// 172.16.50/80 address and are excluded; if one gains one, add it here.
var labStacks16473 = []labStack{
	{"standalone (xpf-test.conf)", []string{"test/incus/xpf-test.conf"}},
	{"legacy local (ha-cluster.conf)", []string{
		"docs/ha-cluster.conf",
		"test/incus/xpf-cluster-fw0.conf",
		"test/incus/xpf-cluster-fw1.conf",
	}},
	{"loss legacy (ha-cluster-loss.conf)", []string{"docs/ha-cluster-loss.conf"}},
	{"loss userspace (ha-cluster-userspace.conf)", []string{"docs/ha-cluster-userspace.conf"}},
	{"tcp (ha-cluster-tcp.conf)", []string{"docs/ha-cluster-tcp.conf"}},
	{"udp (ha-cluster-udp.conf)", []string{"docs/ha-cluster-udp.conf"}},
}

// acceptedShared16473 maps an address to the two stacks allowed to
// share it, with the §3.3 justification. Keep this list empty of new
// entries unless the overlap is same-stack-by-construction and
// documented in docs/incus-tcp-udp-plan.md §3.3.
var acceptedShared16473 = map[string][2]string{
	// Legacy-loss RETH .7 on VLAN 80 and the loss userspace pool-SNAT /
	// proxy-ARP .7: the pre-known leg the issue explicitly tolerates.
	"172.16.80.7": {"loss legacy (ha-cluster-loss.conf)", "loss userspace (ha-cluster-userspace.conf)"},
}

var sharedNets16473 = []netip.Prefix{
	netip.MustParsePrefix("172.16.50.0/24"),
	netip.MustParsePrefix("172.16.80.0/24"),
	netip.MustParsePrefix("2001:559:8585:50::/64"),
	netip.MustParsePrefix("2001:559:8585:80::/64"),
}

func inSharedNet16473(ip netip.Addr) bool {
	for _, n := range sharedNets16473 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// claim is one stack's claim on one shared-segment address.
type claim16473 struct {
	stack string
	kind  string // interface | vrrp | proxy-arp | pool <name> | nat64-pool <name>
}

// claimsForFile compiles one shipped config and extracts every
// shared-segment address claim: interface/VRRP addresses (ARP/ND
// owners), proxy-ARP addresses (ARP/ND owners), and NAT source /
// NAT64 pool addresses (return-traffic destinations).
func claimsForFile16473(t *testing.T, rel string) map[string][]claim16473 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	// Per-node files bake their node number literally (xpf-cluster-fw1
	// says `node 1`), so compile each file as its own node; CheckText's
	// nodeID drives the identity cross-check. Default 0, fw1 overrides.
	nodeID := 0
	if strings.Contains(rel, "fw1") {
		nodeID = 1
	}
	cfg, err := CheckText(strings.ReplaceAll(string(raw), "${node}", "node0"), nodeID)
	if err != nil {
		t.Fatalf("compile %s: %v", rel, err)
	}
	out := map[string][]claim16473{}
	add := func(addr, kind string) {
		s := addr
		if p, err := netip.ParsePrefix(addr); err == nil {
			s = p.Addr().String()
		} else if a, err := netip.ParseAddr(addr); err == nil {
			s = a.String()
		} else {
			return
		}
		ip, err := netip.ParseAddr(s)
		if err != nil || !inSharedNet16473(ip) {
			return
		}
		out[s] = append(out[s], claim16473{kind: kind})
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			for _, a := range unit.Addresses {
				add(a, "interface")
			}
			for _, vg := range unit.VRRPGroups {
				if vg == nil {
					continue
				}
				for _, a := range vg.VirtualAddresses {
					add(a, "vrrp")
				}
			}
		}
	}
	nat := cfg.Security.NAT
	for _, e := range nat.ProxyARP {
		if e == nil {
			continue
		}
		for _, a := range e.Addresses {
			add(a, "proxy-arp")
		}
	}
	for name, pool := range nat.SourcePools {
		if pool == nil {
			continue
		}
		add(pool.Address, "pool "+name)
		for _, a := range pool.Addresses {
			add(a, "pool "+name)
		}
	}
	if nat.Destination != nil {
		for name, pool := range nat.Destination.Pools {
			if pool == nil {
				continue
			}
			add(pool.Address, "dst-pool "+name)
			for _, a := range pool.Addresses {
				add(a, "dst-pool "+name)
			}
		}
	}
	// NAT64 source pools are named references into SourcePools on some
	// shapes and carry their own pool on others; the SourcePools walk
	// above already covers the pool definition itself, which is where
	// the address lives. Assert the reference resolves so a renamed
	// pool cannot silently drop out of the census.
	for _, rs := range nat.NAT64 {
		if rs == nil || rs.SourcePool == "" {
			continue
		}
		if _, ok := nat.SourcePools[rs.SourcePool]; !ok {
			t.Errorf("%s: NAT64 rule-set %s references undefined source-pool %q; census cannot see its address",
				rel, rs.Name, rs.SourcePool)
		}
	}
	return out
}

func TestSharedSegmentAddressPlan16473(t *testing.T) {
	// addr -> stack -> kinds
	owners := map[string]map[string][]string{}
	for _, st := range labStacks16473 {
		for _, rel := range st.files {
			for addr, claims := range claimsForFile16473(t, rel) {
				if owners[addr] == nil {
					owners[addr] = map[string][]string{}
				}
				for _, c := range claims {
					owners[addr][st.name] = append(owners[addr][st.name],
						fmt.Sprintf("%s (%s)", c.kind, rel))
				}
			}
		}
	}
	addrs := make([]string, 0, len(owners))
	for a := range owners {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	for _, addr := range addrs {
		stacks := owners[addr]
		if len(stacks) <= 1 {
			continue
		}
		names := make([]string, 0, len(stacks))
		for s := range stacks {
			names = append(names, s)
		}
		sort.Strings(names)
		if acc, ok := acceptedShared16473[addr]; ok {
			if len(names) == 2 && ((names[0] == acc[0] && names[1] == acc[1]) || (names[0] == acc[1] && names[1] == acc[0])) {
				t.Logf("ACCEPTED %s shared by %v (documented in docs/incus-tcp-udp-plan.md §3.3)", addr, names)
				continue
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "COLLISION %s claimed by %d stacks on the shared segment:", addr, len(names))
		for _, s := range names {
			fmt.Fprintf(&b, "\n  %s: %s", s, strings.Join(stacks[s], ", "))
		}
		b.WriteString("\n  move one claim to an address no other stack uses and register it in docs/incus-tcp-udp-plan.md §3.3 (#16473)")
		t.Error(b.String())
	}
}

// The standalone's two pools must sit on standalone-only addresses and
// BOTH must be proxy-ARPed: the NAT64 pool previously had no ARP
// answerer at all (round-2 A92-03), and proxy-ARPing the old .11 would
// have fought the udp RETH. This pins the fix direction, not just the
// absence of today's collision.
func TestStandalonePoolsProxyARPed16473(t *testing.T) {
	claims := claimsForFile16473(t, "test/incus/xpf-test.conf")
	pools := map[string]string{} // addr -> kind
	arped := map[string]bool{}
	for addr, cs := range claims {
		for _, c := range cs {
			if strings.HasPrefix(c.kind, "pool ") {
				pools[addr] = c.kind
			}
			if c.kind == "proxy-arp" {
				arped[addr] = true
			}
		}
	}
	if len(pools) == 0 {
		t.Fatal("xpf-test.conf: no NAT pools found on the shared segment; census extracted nothing")
	}
	for addr, kind := range pools {
		if !arped[addr] {
			t.Errorf("xpf-test.conf: %s at %s is not proxy-ARPed on ge-0/0/3.50; return traffic blackholes (A92-03 direction, #16473)", kind, addr)
		}
	}
	// The two historical collisions must stay gone even if the census
	// above is ever weakened.
	for _, gone := range []string{"172.16.50.6", "172.16.50.11"} {
		if kind, ok := pools[gone]; ok {
			t.Errorf("xpf-test.conf: %s still claims %s, owned by another stack (#16473)", kind, gone)
		}
		if arped[gone] {
			t.Errorf("xpf-test.conf: still proxy-ARPs %s, owned by another stack (#16473)", gone)
		}
	}
}
