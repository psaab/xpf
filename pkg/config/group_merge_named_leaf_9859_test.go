package config

import (
	"slices"
	"sort"
	"strings"
	"testing"
)

func compileSchedulers9859(t *testing.T, text string) map[string]*CoSScheduler {
	t.Helper()
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if err := SchemaValidate(tree, cfg); err != nil {
		t.Fatalf("SchemaValidate rejected the fixture: %v", err)
	}
	if cfg.ClassOfService == nil {
		t.Fatalf("ClassOfService is nil, want schedulers")
	}
	return cfg.ClassOfService.Schedulers
}

// TestGroupNamedLeafDifferentSyslogHosts9859 is the issue's primary RED-on-
// revert guard. A group leaf naming one host must survive beside an inline leaf
// naming another host; the old leafListPeer keyword match dropped the group.
func TestGroupNamedLeafDifferentSyslogHosts9859(t *testing.T) {
	cases := []struct {
		name   string
		group  string
		inline string
	}{
		{
			name:   "plain leaves group A inline B",
			group:  `host 10.0.0.1;`,
			inline: `host 10.0.0.2;`,
		},
		{
			name:   "plain leaves group B inline A",
			group:  `host 10.0.0.2;`,
			inline: `host 10.0.0.1;`,
		},
		{
			name:   "packed leaves with source order A then B",
			group:  `host 10.0.0.1 any any; host 10.0.0.2 local0 info;`,
			inline: `host 10.0.0.1;`,
		},
		{
			name:   "packed leaves with source order B then A",
			group:  `host 10.0.0.2 local0 info; host 10.0.0.1 any any;`,
			inline: `host 10.0.0.1;`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := `groups { G { system { syslog { ` + tc.group + ` } } } } apply-groups G; system { syslog { ` + tc.inline + ` } }`
			hosts := compileSyslogHosts9855(t, text)
			var got []string
			for _, host := range hosts {
				got = append(got, host.Address)
			}
			sort.Strings(got)
			if !slices.Equal(got, []string{"10.0.0.1", "10.0.0.2"}) {
				t.Fatalf("syslog hosts = %v, want both named instances", got)
			}
		})
	}
}

// TestGroupNamedLeafDifferentSchedulers9859 proves that children-bearing
// multi schedulers are named containers, not value lists: distinct names both
// survive, including when the inline spelling is braced.
func TestGroupNamedLeafDifferentSchedulers9859(t *testing.T) {
	cases := []struct {
		name   string
		inline string
	}{
		{name: "inline leaf", inline: `schedulers inline-sched;`},
		{name: "inline braced control", inline: `schedulers inline-sched { }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := `groups { G { class-of-service { schedulers group-sched; } } } apply-groups G; class-of-service { ` + tc.inline + ` }`
			schedulers := compileSchedulers9859(t, text)
			if len(schedulers) != 2 || schedulers["group-sched"] == nil || schedulers["inline-sched"] == nil {
				t.Fatalf("schedulers = %v, want group-sched and inline-sched", schedulers)
			}
		})
	}

	// A braced group is the shape control for the issue's original table row.
	schedulers := compileSchedulers9859(t,
		`groups { G { class-of-service { schedulers group-sched { } } } } apply-groups G; class-of-service { schedulers inline-sched; }`)
	if len(schedulers) != 2 || schedulers["group-sched"] == nil || schedulers["inline-sched"] == nil {
		t.Fatalf("braced group schedulers = %v, want both named instances", schedulers)
	}
}

// TestGroupNamedLeafSameInstanceKeepsInlineOverride9859 pins same-instance
// leaf handling. The explicit inline facility remains authoritative.
func TestGroupNamedLeafSameInstanceKeepsInlineOverride9859(t *testing.T) {
	hosts := compileSyslogHosts9855(t,
		`groups { G { system { syslog { host 10.0.0.1 any emergency; } } } } apply-groups G; system { syslog { host 10.0.0.1 any info; } }`)
	if len(hosts) != 1 {
		t.Fatalf("hosts = %+v, want one same-instance destination", hosts)
	}
	if got := facilities9855(hosts); !slices.Equal(got, []SyslogFacility{{Facility: "any", Severity: "info"}}) {
		t.Fatalf("facilities = %+v, want inline severity", got)
	}
}

// TestGroupNamedLeafSameInstanceBracedPeer9859 keeps a same-instance braced
// peer on the existing merge path. The leaf group spelling must not be
// adopted beside its inline braced spelling.
func TestGroupNamedLeafSameInstanceBracedPeer9859(t *testing.T) {
	text := `groups { G { system { syslog { host 10.0.0.1; } } } } apply-groups G; system { syslog { host 10.0.0.1 { any info; } } }`
	tree := parseHierarchical(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("expand: %v", err)
	}
	n := 0
	var walk func([]*Node)
	walk = func(nodes []*Node) {
		for _, node := range nodes {
			if len(node.Keys) >= 2 && node.Keys[0] == "host" && node.Keys[1] == "10.0.0.1" {
				n++
			}
			walk(node.Children)
		}
	}
	walk(tree.Children)
	if n != 1 {
		t.Fatalf("want exactly one same-instance host node, got %d", n)
	}
	hosts := compileSyslogHosts9855(t, text)
	if len(hosts) != 1 || !slices.Equal(hosts[0].Facilities, []SyslogFacility{{Facility: "any", Severity: "info"}}) {
		t.Fatalf("hosts = %+v, want inline braced facilities", hosts)
	}
}

// TestGroupNamedLeafUnexpandableTailBracedPeer9859 keeps an unexpandable
// packed tail on the conservative override path. A same-instance braced peer
// must not be duplicated merely because the group tail is unknown.
func TestGroupNamedLeafUnexpandableTailBracedPeer9859(t *testing.T) {
	text := `groups { G { class-of-service { schedulers sched-a unknown-tail edge; } } } apply-groups G; class-of-service { schedulers sched-a { priority high; } }`

	cfgTree := parseHierarchical(t, text)
	cfg, err := CompileConfigLenient(cfgTree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if cfg.ClassOfService == nil || len(cfg.ClassOfService.Schedulers) != 1 {
		t.Fatalf("schedulers = %+v, want one conservative override", cfg.ClassOfService)
	}
	scheduler := cfg.ClassOfService.Schedulers["sched-a"]
	if scheduler == nil || scheduler.Priority != "high" {
		t.Fatalf("scheduler = %+v, want inline braced priority", scheduler)
	}

	expanded := parseHierarchical(t, text)
	if err := expanded.ExpandGroups(); err != nil {
		t.Fatalf("expand: %v", err)
	}
	n := 0
	var walk func([]*Node)
	walk = func(nodes []*Node) {
		for _, node := range nodes {
			if len(node.Keys) >= 2 && node.Keys[0] == "schedulers" && node.Keys[1] == "sched-a" {
				n++
			}
			walk(node.Children)
		}
	}
	walk(expanded.Children)
	if n != 1 {
		t.Fatalf("want exactly one scheduler node after conservative override, got %d", n)
	}
}

// TestGroupValueListNamedLeavesStayOnKeywordPath9859 keeps valueList leaves
// out of identity matching. The existing next-hop rows cover that schema
// valueList; these NTP and DHCP rows cover the two modifier-bearing lists.
func TestGroupValueListNamedLeavesStayOnKeywordPath9859(t *testing.T) {
	t.Run("NTP server list", func(t *testing.T) {
		text := `groups { G { system { ntp { server 192.0.2.2; } } } } apply-groups G; system { ntp { server [ 192.0.2.1 192.0.2.2 ]; } }`
		tree := parseHierarchical(t, text)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if !slices.Equal(cfg.System.NTPServers, []string{"192.0.2.1", "192.0.2.2"}) {
			t.Fatalf("NTP servers = %v, want inline list without a duplicate", cfg.System.NTPServers)
		}
	})

	t.Run("DHCP interface list", func(t *testing.T) {
		text := `groups { G { system { services { dhcp-local-server { group g { interface ge-0/0/1.0; } } } } } } apply-groups G; system { services { dhcp-local-server { group g { interface [ ge-0/0/0.0 ge-0/0/1.0 ]; } } } }`
		tree := parseHierarchical(t, text)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		server := cfg.System.DHCPServer.DHCPLocalServer
		if server == nil || server.Groups["g"] == nil {
			t.Fatalf("DHCP group g missing from %+v", server)
		}
		if got := server.Groups["g"].Interfaces; !slices.Equal(got, []string{"ge-0/0/0.0", "ge-0/0/1.0"}) {
			t.Fatalf("DHCP interfaces = %v, want inline list without a duplicate", got)
		}
	})
}

// TestGroupCanonicalAreaKeepsKeywordOverride9859 pins the OSPF canonical
// alias registry. Decimal and dotted-zero spellings share one canonical
// identity, while different area IDs remain separate instances.
func TestGroupCanonicalAreaKeepsKeywordOverride9859(t *testing.T) {
	text := `groups { G { protocols { ospf { area 0 area-type stub; } } } } apply-groups G; protocols { ospf { area 0.0.0.0; } }`
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.OSPF == nil || len(cfg.Protocols.OSPF.Areas) != 1 {
		t.Fatalf("OSPF areas = %+v, want one canonical instance", cfg.Protocols.OSPF)
	}
	area := cfg.Protocols.OSPF.Areas[0]
	if area.ID != "0.0.0.0" || area.AreaType != "" {
		t.Fatalf("OSPF area = %+v, want inline ID 0.0.0.0 with normal area type", area)
	}
	t.Run("different area IDs remain distinct", func(t *testing.T) {
		text := `groups { G { protocols { ospf { area 1 area-type stub; } } } } apply-groups G; protocols { ospf { area 2; } }`
		tree := parseHierarchical(t, text)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if cfg.Protocols.OSPF == nil || len(cfg.Protocols.OSPF.Areas) != 2 {
			t.Fatalf("OSPF areas = %+v, want distinct areas 1 and 2", cfg.Protocols.OSPF)
		}
		seen := map[string]bool{}
		for _, area := range cfg.Protocols.OSPF.Areas {
			seen[area.ID] = true
		}
		if !seen["1"] || !seen["2"] {
			t.Fatalf("OSPF area IDs = %v, want both 1 and 2", seen)
		}
	})
}

// TestGroupCanonicalRedundancyGroupKeepsKeywordOverride9859 pins the
// chassis compiler's Atoi-folded redundancy-group identity. The inline
// spelling wins before compileChassis's int-keyed last-wins fold can alias
// the two raw tokens.
func TestGroupCanonicalRedundancyGroupKeepsKeywordOverride9859(t *testing.T) {
	text := `groups { G { chassis { cluster { redundancy-group 01 node 0 priority 200; } } } } apply-groups G; chassis { cluster { cluster-id 1; authentication-key test-cluster-psk-9859; node 0; redundancy-group 1 node 0 priority 100; } }`
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatalf("chassis cluster missing from %+v", cfg.Chassis)
	}
	rgs := cfg.Chassis.Cluster.RedundancyGroups
	if len(rgs) != 1 || rgs[0].ID != 1 {
		t.Fatalf("redundancy groups = %+v, want one RG with canonical ID 1", rgs)
	}
	if got := rgs[0].NodePriorities[0]; got != 100 {
		t.Fatalf("RG 1 node 0 priority = %d, want inline priority 100", got)
	}
	t.Run("different RG IDs remain distinct", func(t *testing.T) {
		text := `groups { G { chassis { cluster { redundancy-group 2 node 0 priority 200; } } } } apply-groups G; chassis { cluster { cluster-id 1; authentication-key test-cluster-psk-9859; node 0; redundancy-group 1 node 0 priority 100; } }`
		tree := parseHierarchical(t, text)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if cfg.Chassis.Cluster == nil || len(cfg.Chassis.Cluster.RedundancyGroups) != 2 {
			t.Fatalf("redundancy groups = %+v, want distinct IDs 1 and 2", cfg.Chassis.Cluster)
		}
		priority := map[int]int{}
		for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
			priority[rg.ID] = rg.NodePriorities[0]
		}
		if priority[1] != 100 || priority[2] != 200 {
			t.Fatalf("redundancy-group priorities = %v, want ID1=100 and ID2=200", priority)
		}
	})

}

// TestGroupCanonicalInterfaceUnitKeepsKeywordOverride9859 pins the regular
// interface unit alias. CanonicalLogicalUnit folds 01 and 1 into the same
// int-keyed map, so the group description must not survive the inline unit.

func TestGroupCanonicalInterfaceUnitKeepsKeywordOverride9859(t *testing.T) {
	text := `groups { G { interfaces { ge-0/0/0 { unit 01 description group-unit; } } } } apply-groups G; interfaces { ge-0/0/0 { unit 1 description inline-unit; } }`
	tree := parseHierarchical(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	ifaces := tree.FindChild("interfaces")
	if ifaces == nil {
		t.Fatalf("expanded interface tree missing from %+v", tree)
	}
	iface := ifaces.FindChild("ge-0/0/0")
	if iface == nil {
		t.Fatalf("expanded interface ge-0/0/0 missing from %+v", ifaces)
	}
	units := iface.FindChildren("unit")
	if len(units) != 1 || !slices.Equal(units[0].Keys,
		[]string{"unit", "1", "description", "inline-unit"}) {
		t.Fatalf("expanded interface units = %+v, want only inline canonical unit", units)
	}

	t.Run("different unit IDs remain distinct", func(t *testing.T) {
		text := `groups { G { interfaces { ge-0/0/0 { unit 2 description group-unit; } } } } apply-groups G; interfaces { ge-0/0/0 { unit 1 description inline-unit; } }`
		tree := parseHierarchical(t, text)
		if err := tree.ExpandGroups(); err != nil {
			t.Fatalf("ExpandGroups: %v", err)
		}
		ifaces := tree.FindChild("interfaces")
		iface := ifaces.FindChild("ge-0/0/0")
		units := iface.FindChildren("unit")
		if len(units) != 2 {
			t.Fatalf("expanded interface units = %+v, want distinct IDs 1 and 2", units)
		}
		seen := map[string]bool{}
		for _, unit := range units {
			if len(unit.Keys) >= 2 {
				seen[unit.Keys[1]] = true
			}
		}
		if !seen["1"] || !seen["2"] {
			t.Fatalf("expanded interface unit IDs = %v, want both 1 and 2", seen)
		}
	})
}

// TestGroupCanonicalCoSInterfaceUnitKeepsKeywordOverride9859 pins the
// class-of-service interfaces unit alias independently of regular interfaces.
func TestGroupCanonicalCoSInterfaceUnitKeepsKeywordOverride9859(t *testing.T) {
	text := `groups { G { class-of-service { interfaces ge-0/0/0 { unit 01 scheduler-map group-map; } } } } apply-groups G; class-of-service { interfaces ge-0/0/0 { unit 1 scheduler-map inline-map; } }`
	tree := parseHierarchical(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	cos := tree.FindChild("class-of-service")
	if cos == nil {
		t.Fatalf("expanded class-of-service tree missing from %+v", tree)
	}
	iface := cos.FindChild("interfaces")
	if iface == nil {
		t.Fatalf("expanded CoS interface tree missing from %+v", cos)
	}
	units := iface.FindChildren("unit")
	if len(units) != 1 || !slices.Equal(units[0].Keys,
		[]string{"unit", "1", "scheduler-map", "inline-map"}) {
		t.Fatalf("expanded CoS interface units = %+v, want only inline canonical unit", units)
	}
	t.Run("different unit IDs remain distinct", func(t *testing.T) {
		text := `groups { G { class-of-service { interfaces ge-0/0/0 { unit 2 scheduler-map group-map; } } } } apply-groups G; class-of-service { interfaces ge-0/0/0 { unit 1 scheduler-map inline-map; } }`
		tree := parseHierarchical(t, text)
		if err := tree.ExpandGroups(); err != nil {
			t.Fatalf("ExpandGroups: %v", err)
		}
		cos := tree.FindChild("class-of-service")
		iface := cos.FindChild("interfaces")
		units := iface.FindChildren("unit")
		if len(units) != 2 {
			t.Fatalf("expanded CoS interface units = %+v, want distinct IDs 1 and 2", units)
		}
		seen := map[string]bool{}
		for _, unit := range units {
			if len(unit.Keys) >= 2 {
				seen[unit.Keys[1]] = true
			}
		}
		if !seen["1"] || !seen["2"] {
			t.Fatalf("expanded CoS interface unit IDs = %v, want both 1 and 2", seen)
		}
	})

}

// TestGroupCoSShapingRateKeepsInlineScalar9859 guards the exception for CoS
// shaping-rate. Its schema has an optional burst-size child, but the rate
// itself is a scalar binding and must keep inline-wins semantics.
func TestGroupCoSShapingRateKeepsInlineScalar9859(t *testing.T) {
	cases := []struct {
		name          string
		unit          bool
		group, inline string
		wantBurst     string
	}{
		{
			name: "interface scalar", group: `shaping-rate 10m;`,
			inline: `shaping-rate 20m;`,
		},
		{
			name: "interface with burst-size", group: `shaping-rate 10m burst-size 1m;`,
			inline: `shaping-rate 20m burst-size 2m;`, wantBurst: "2m",
		},
		{
			name: "unit scalar", unit: true, group: `shaping-rate 10m;`,
			inline: `shaping-rate 20m;`,
		},
		{
			name: "unit with burst-size", unit: true,
			group:  `shaping-rate 10m burst-size 1m;`,
			inline: `shaping-rate 20m burst-size 2m;`, wantBurst: "2m",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var groupBody, inlineBody string
			if tc.unit {
				groupBody = `interfaces ge-0/0/0 { unit 0 ` + tc.group + ` }`
				inlineBody = `interfaces ge-0/0/0 { unit 0 ` + tc.inline + ` }`
			} else {
				groupBody, inlineBody = `interfaces ge-0/0/0 { `+tc.group+` }`,
					`interfaces ge-0/0/0 { `+tc.inline+` }`
			}
			text := `groups { G { class-of-service { ` + groupBody + ` } } } apply-groups G; class-of-service { ` + inlineBody + ` }`
			tree := parseHierarchical(t, text)
			if err := tree.ExpandGroups(); err != nil {
				t.Fatalf("ExpandGroups: %v", err)
			}
			cos := tree.FindChild("class-of-service")
			if cos == nil {
				t.Fatalf("expanded class-of-service tree missing from %+v", tree)
			}
			iface := cos.FindChild("interfaces")
			if iface == nil {
				t.Fatalf("expanded CoS interface tree missing from %+v", cos)
			}
			var shaping []*Node
			if tc.unit {
				units := iface.FindChildren("unit")
				if len(units) != 1 {
					t.Fatalf("expanded CoS units = %+v, want one inline unit", units)
				}
				shaping = units[0].FindChildren("shaping-rate")
			} else {
				shaping = iface.FindChildren("shaping-rate")
			}
			if len(shaping) != 1 {
				t.Fatalf("expanded shaping-rate nodes = %+v, want one inline scalar", shaping)
			}
			rate, burst := "", ""
			var visit func(*Node)
			visit = func(n *Node) {
				for i := 0; i+1 < len(n.Keys); i++ {
					switch n.Keys[i] {
					case "shaping-rate":
						rate = n.Keys[i+1]
					case "burst-size":
						burst = n.Keys[i+1]
					}
				}
				for _, child := range n.Children {
					visit(child)
				}
			}
			visit(shaping[0])
			if rate != "20m" || burst != tc.wantBurst {
				t.Fatalf("expanded shaping-rate values = rate %q burst %q, want inline rate 20m burst %q",
					rate, burst, tc.wantBurst)
			}
		})
	}
}

// TestGroupCoSShapingRateOrderedGroups9859 keeps scalar precedence stable when
// multiple groups contribute different shaping rates. An unrelated exclusion
// must not switch the merge into a provenance-dependent path.
func TestGroupCoSShapingRateOrderedGroups9859(t *testing.T) {
	cases := []struct {
		name, order, want string
		except            bool
	}{
		{name: "G1 then G2", order: "G1 G2", want: "10m"},
		{name: "G2 then G1", order: "G2 G1", want: "20m"},
		{name: "G1 then G2 with unrelated except", order: "G1 G2", want: "10m", except: true},
		{name: "G2 then G1 with unrelated except", order: "G2 G1", want: "20m", except: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			except := ""
			if tc.except {
				except = ` system { apply-groups-except NEVER; }`
			}
			text := `groups { G1 { class-of-service { interfaces ge-0/0/0 { shaping-rate 10m burst-size 1m; } } } G2 { class-of-service { interfaces ge-0/0/0 { shaping-rate 20m burst-size 2m; } } } } apply-groups [ ` + tc.order + ` ]; class-of-service { interfaces ge-0/0/0 { } }` + except
			tree := parseHierarchical(t, text)
			if err := tree.ExpandGroups(); err != nil {
				t.Fatalf("ExpandGroups: %v", err)
			}
			cos := tree.FindChild("class-of-service")
			if cos == nil {
				t.Fatalf("expanded class-of-service tree missing from %+v", tree)
			}
			iface := cos.FindChild("interfaces")
			if iface == nil {
				t.Fatalf("expanded CoS interface tree missing from %+v", cos)
			}
			shaping := iface.FindChildren("shaping-rate")
			if len(shaping) != 1 {
				t.Fatalf("expanded shaping-rate nodes = %+v, want one ordered scalar", shaping)
			}
			if len(shaping[0].Keys) < 2 || shaping[0].Keys[1] != tc.want {
				t.Fatalf("ordered shaping-rate = %q, want %q", shaping[0].Keys, tc.want)
			}
		})
	}
}

// TestGroupCanonicalWireGuardPeerKeepsKeywordOverride9859 pins the
// lowercase pubkey identity at both schema locations: interface-level tunnel
// peers and peers nested under an interface unit.
func TestGroupCanonicalWireGuardPeerKeepsKeywordOverride9859(t *testing.T) {
	privateKey := strings.Repeat("cd", 32)
	basePeer := strings.Repeat("ef", 32)
	upperPeer := strings.Repeat("ab", 32)
	lowerPeer := strings.ToLower(upperPeer)
	otherPeer := strings.Repeat("12", 32)

	t.Run("interface tunnel peer", func(t *testing.T) {
		text := `groups { G { interfaces { wg0 { tunnel { wireguard { peer ` + strings.ToUpper(upperPeer) + `; } } } } } } apply-groups G; interfaces { wg0 { tunnel { mode wireguard; wireguard { listen-port 51820; private-key ` + privateKey + `; peer ` + lowerPeer + `; } } } }`
		tree := parseHierarchical(t, text)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		iface := cfg.Interfaces.Interfaces["wg0"]
		if iface == nil || iface.Tunnel == nil || len(iface.Tunnel.WgPeers) != 1 ||
			iface.Tunnel.WgPeers[0].PublicKeyHex != lowerPeer {
			t.Fatalf("interface WireGuard peers = %+v, want only inline lowercase peer", iface)
		}
	})
	t.Run("interface distinct peers remain distinct", func(t *testing.T) {
		text := `groups { G { interfaces { wg0 { tunnel { wireguard { peer ` + upperPeer + `; } } } } } } apply-groups G; interfaces { wg0 { tunnel { mode wireguard; wireguard { listen-port 51820; private-key ` + privateKey + `; peer ` + basePeer + `; } } } }`
		tree := parseHierarchical(t, text)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		iface := cfg.Interfaces.Interfaces["wg0"]
		if iface == nil || iface.Tunnel == nil {
			t.Fatalf("interface WireGuard tunnel missing from %+v", iface)
		}
		seen := map[string]bool{}
		for _, peer := range iface.Tunnel.WgPeers {
			seen[peer.PublicKeyHex] = true
		}
		if len(seen) != 2 || !seen[basePeer] || !seen[upperPeer] {
			t.Fatalf("interface WireGuard peers = %+v, want distinct base and group keys",
				iface.Tunnel.WgPeers)
		}
	})

	t.Run("unit tunnel peer", func(t *testing.T) {
		text := `groups { G { interfaces { wg0 { unit 1 { tunnel { wireguard { peer ` + strings.ToUpper(upperPeer) + `; } } } } } } } apply-groups G; interfaces { wg0 { tunnel { mode wireguard; wireguard { listen-port 51820; private-key ` + privateKey + `; peer ` + basePeer + `; } } unit 1 { tunnel { wireguard { peer ` + lowerPeer + `; } } } } }`
		tree := parseHierarchical(t, text)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		iface := cfg.Interfaces.Interfaces["wg0"]
		if iface == nil || iface.Units[1] == nil || iface.Units[1].Tunnel == nil {
			t.Fatalf("unit 1 WireGuard tunnel missing from %+v", iface)
		}
		seen := map[string]bool{}
		for _, peer := range iface.Units[1].Tunnel.WgPeers {
			seen[peer.PublicKeyHex] = true
		}
		if len(seen) != 2 || !seen[basePeer] || !seen[lowerPeer] {
			t.Fatalf("unit 1 WireGuard peers = %+v, want inherited base and inline lowercase peer only",
				iface.Units[1].Tunnel.WgPeers)
		}
	})
	t.Run("unit distinct peers remain distinct", func(t *testing.T) {
		text := `groups { G { interfaces { wg0 { unit 1 { tunnel { wireguard { peer ` + upperPeer + `; } } } } } } } apply-groups G; interfaces { wg0 { tunnel { mode wireguard; wireguard { listen-port 51820; private-key ` + privateKey + `; peer ` + basePeer + `; } } unit 1 { tunnel { wireguard { peer ` + otherPeer + `; } } } } }`
		tree := parseHierarchical(t, text)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		iface := cfg.Interfaces.Interfaces["wg0"]
		if iface == nil || iface.Units[1] == nil || iface.Units[1].Tunnel == nil {
			t.Fatalf("unit 1 WireGuard tunnel missing from %+v", iface)
		}
		seen := map[string]bool{}
		for _, peer := range iface.Units[1].Tunnel.WgPeers {
			seen[peer.PublicKeyHex] = true
		}
		if len(seen) != 3 || !seen[basePeer] || !seen[otherPeer] || !seen[upperPeer] {
			t.Fatalf("unit 1 WireGuard peers = %+v, want inherited base plus distinct inline and group keys",
				iface.Units[1].Tunnel.WgPeers)
		}
	})

}

// TestGroupCanonicalVRRPKeepsKeywordOverride9859 pins the VRRP canonical
// alias registry independently of OSPF. Atoi canonicalizes 01 and 1 in the
// compiler, so the inline priority must keep precedence.
func TestGroupCanonicalVRRPKeepsKeywordOverride9859(t *testing.T) {
	addr := func(inner string) string {
		return `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { ` + inner + ` } } } } }`
	}
	text := `groups { G { ` + addr(`vrrp-group 01 priority 200;`) + ` } } apply-groups G; ` + addr(`vrrp-group 1 priority 100 virtual-address 10.0.61.1/24;`)
	vg := vrrpGroup9855(t, text)
	if vg.Priority != 100 {
		t.Fatalf("VRRP priority = %d, want inline priority 100 for canonical alias", vg.Priority)
	}
	if !slices.Equal(vg.VirtualAddresses, []string{"10.0.61.1/24"}) {
		t.Fatalf("VRRP virtual-addresses = %v, want inline address only", vg.VirtualAddresses)
	}
	t.Run("different VRRP IDs remain distinct", func(t *testing.T) {
		text := `groups { G { ` + addr(`vrrp-group 2 priority 200 virtual-address 10.0.61.3/24;`) + ` } } apply-groups G; ` + addr(`vrrp-group 1 priority 100 virtual-address 10.0.61.1/24;`)
		tree := parseHierarchical(t, text)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		iface := cfg.Interfaces.Interfaces["ge-0/0/0"]
		if iface == nil || iface.Units[0] == nil || len(iface.Units[0].VRRPGroups) != 2 {
			t.Fatalf("VRRP groups = %+v, want distinct IDs 1 and 2", iface)
		}
		priority := map[int]int{}
		for _, group := range iface.Units[0].VRRPGroups {
			priority[group.ID] = group.Priority
		}
		if priority[1] != 100 || priority[2] != 200 {
			t.Fatalf("VRRP priorities = %v, want ID1=100 and ID2=200", priority)
		}
	})

}

// TestGroupPackedDifferentInstanceAdopts9859 pins the packed-tail boundary:
// same-instance packed tails retain #9855 promotion, while a different host
// is adopted rather than suppressed by the promoted same-keyword sibling.
func TestGroupPackedDifferentInstanceAdopts9859(t *testing.T) {
	text := `groups { G { system { syslog { host 10.0.0.1 any any; host 10.0.0.2 local0 info; } } } } apply-groups G; system { syslog { host 10.0.0.1; } }`
	hosts := compileSyslogHosts9855(t, text)
	if len(hosts) != 2 {
		t.Fatalf("syslog hosts = %+v, want two packed instances", hosts)
	}
	byAddress := map[string]*SyslogHostConfig{}
	for _, host := range hosts {
		byAddress[host.Address] = host
	}
	groupHost, groupOK := byAddress["10.0.0.1"]
	inlineHost, inlineOK := byAddress["10.0.0.2"]
	if !groupOK || !inlineOK || !slices.Equal(groupHost.Facilities, []SyslogFacility{{Facility: "any", Severity: "any"}}) {
		t.Fatalf("syslog hosts by address = %+v, want packed group and inline instances", byAddress)
	}
	if len(inlineHost.Facilities) != 1 || inlineHost.Facilities[0].Facility != "local0" || inlineHost.Facilities[0].Severity != "info" {
		t.Fatalf("inline host 10.0.0.2 = %+v, want its packed facility", inlineHost)
	}
}

// TestGroupPackedDifferentInstanceParity10056 runs the same source leaves in
// both orders. Promotion of one same-keyword instance must not make the other
// instance depend on source ordering.
func TestGroupPackedDifferentInstanceParity10056(t *testing.T) {
	for _, group := range []string{
		`host 10.0.0.1 any any; host 10.0.0.2 local0 info;`,
		`host 10.0.0.2 local0 info; host 10.0.0.1 any any;`,
	} {
		hosts := compileSyslogHosts9855(t,
			`groups { G { system { syslog { `+group+` } } } } apply-groups G; system { syslog { host 10.0.0.1; } }`)
		if len(hosts) != 2 {
			t.Fatalf("group order %q: hosts = %+v, want two", group, hosts)
		}
		seen := map[string]bool{}
		for _, host := range hosts {
			seen[host.Address] = true
		}
		if !seen["10.0.0.1"] || !seen["10.0.0.2"] {
			t.Fatalf("group order %q: hosts = %+v, want both addresses", group, hosts)
		}
	}
}

// TestGroupBracketedAddressUnion9859 pins the #10234 round-2 P1: family
// inet/inet6 `address` is a named-container schema site (children for
// primary/preferred/vrrp-group), so namedLeafPeer9859 admits it — but
// identitySpan9855 compares Keys[:2] only. A group single `address B` beside
// an inline bracketed `address [A B]` compared [address B] vs [address A],
// missed, and adopted: the unit compiled [A B B] via #9424 accumulation
// across the two nodes. A bracketed run is multiple ordinary addresses, so
// overlap drops the duplicate, disjoint values survive, and a partially
// overlapping group bracket adopts only its missing members.
func TestGroupBracketedAddressUnion9859(t *testing.T) {
	famBody := func(family, group, inline string) string {
		fam := func(inner string) string {
			return `interfaces { ge-0/0/0 { unit 0 { family ` + family + ` { ` + inner + ` } } } }`
		}
		return `groups { G { ` + fam(group) + ` } } apply-groups G; ` + fam(inline)
	}
	compile := func(t *testing.T, text string) []string {
		t.Helper()
		tree := parseHierarchical(t, text)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if err := SchemaValidate(tree, cfg); err != nil {
			t.Fatalf("SchemaValidate: %v", err)
		}
		unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
		if unit == nil {
			t.Fatalf("fixture broken: no ge-0/0/0 unit 0")
		}
		return unit.Addresses
	}
	t.Run("inet overlap drops the duplicate", func(t *testing.T) {
		got := compile(t, famBody("inet",
			`address 10.0.0.2/24;`,
			`address [ 10.0.0.1/24 10.0.0.2/24 ];`))
		if !slices.Equal(got, []string{"10.0.0.1/24", "10.0.0.2/24"}) {
			t.Fatalf("addresses = %v, want [A B] without the [A B B] duplicate", got)
		}
	})
	t.Run("inet6 overlap drops the duplicate", func(t *testing.T) {
		got := compile(t, famBody("inet6",
			`address 2001:db8::2/64;`,
			`address [ 2001:db8::1/64 2001:db8::2/64 ];`))
		if !slices.Equal(got, []string{"2001:db8::1/64", "2001:db8::2/64"}) {
			t.Fatalf("addresses = %v, want [A B] without the [A B B] duplicate", got)
		}
	})
	t.Run("inet distinct group address survives with aligned mask", func(t *testing.T) {
		text := famBody("inet",
			`address 10.0.0.3/24;`,
			`address [ 10.0.0.1/24 10.0.0.2/24 ];`)
		want := []string{"10.0.0.1/24", "10.0.0.2/24", "10.0.0.3/24"}
		if got := compile(t, text); !slices.Equal(got, want) {
			t.Fatalf("addresses = %v, want %v (a distinct inherited address must survive)", got, want)
		}
		expanded := parseHierarchical(t, text)
		if err := expanded.ExpandGroups(); err != nil {
			t.Fatalf("expand: %v", err)
		}
		var addressNodes []*Node
		var walk func([]*Node)
		walk = func(nodes []*Node) {
			for _, node := range nodes {
				if len(node.Keys) > 0 && node.Keys[0] == "address" {
					addressNodes = append(addressNodes, node)
				}
				walk(node.Children)
			}
		}
		walk(expanded.Children)
		if len(addressNodes) == 0 {
			t.Fatalf("expanded address nodes missing")
		}
		for _, node := range addressNodes {
			if node.KeysBracketed != nil && len(node.KeysBracketed) != len(node.Keys) {
				t.Fatalf("address node %q carries a misaligned bracket mask %v", node.Keys, node.KeysBracketed)
			}
		}
	})
	t.Run("quoted CIDR preserves quote and bracket masks", func(t *testing.T) {
		text := famBody("inet",
			`address "10.0.0.3/24";`,
			`address [ "10.0.0.1/24" 10.0.0.2/24 ];`)
		expanded := parseHierarchical(t, text)
		if err := expanded.ExpandGroups(); err != nil {
			t.Fatalf("expand: %v", err)
		}
		var merged *Node
		var walk func([]*Node)
		walk = func(nodes []*Node) {
			for _, node := range nodes {
				if slices.Contains(node.Keys, "10.0.0.3/24") {
					merged = node
					return
				}
				walk(node.Children)
				if merged != nil {
					return
				}
			}
		}
		walk(expanded.Children)
		if merged == nil {
			t.Fatalf("expanded quoted address member missing")
		}
		if len(merged.KeysQuoted) != len(merged.Keys) ||
			len(merged.KeysBracketed) != len(merged.Keys) {
			t.Fatalf("merged address masks are misaligned: keys=%q quoted=%v bracketed=%v",
				merged.Keys, merged.KeysQuoted, merged.KeysBracketed)
		}
		quotedIndex := slices.Index(merged.Keys, "10.0.0.3/24")
		if !merged.KeyQuoted(quotedIndex) || merged.KeyBracketed(quotedIndex) {
			t.Fatalf("appended quoted CIDR masks = quoted:%v bracketed:%v; want true,false",
				merged.KeyQuoted(quotedIndex), merged.KeyBracketed(quotedIndex))
		}
		inlineIndex := slices.Index(merged.Keys, "10.0.0.1/24")
		if !merged.KeyQuoted(inlineIndex) || !merged.KeyBracketed(inlineIndex) {
			t.Fatalf("inline quoted bracket member masks = quoted:%v bracketed:%v; want true,true",
				merged.KeyQuoted(inlineIndex), merged.KeyBracketed(inlineIndex))
		}
	})
	t.Run("flat quoted member preserves child masks", func(t *testing.T) {
		tree := &ConfigTree{}
		groupLine := `set groups G interfaces ge-0/0/0 unit 0 family inet address [ "10.0.0.3/24" 10.0.0.4/24 ]`
		path, quoted, grouped, err := ParseSetCommandGrouped(groupLine)
		if err != nil {
			t.Fatalf("ParseSetCommandGrouped(%q): %v", groupLine, err)
		}
		if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
			t.Fatalf("SetPathQuotedGrouped(%q): %v", groupLine, err)
		}
		for _, line := range []string{
			`set interfaces ge-0/0/0 unit 0 family inet address [ "10.0.0.1/24" 10.0.0.2/24 ]`,
			`set apply-groups G`,
		} {
			path, err = ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		want := []string{"10.0.0.1/24", "10.0.0.2/24", "10.0.0.3/24", "10.0.0.4/24"}
		got := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].Addresses
		if !slices.Equal(got, want) {
			t.Fatalf("flat-set addresses = %v, want %v", got, want)
		}
		expanded := tree.Clone()
		if err := expanded.ExpandGroups(); err != nil {
			t.Fatalf("expand: %v", err)
		}
		var quotedChild *Node
		var walk func([]*Node)
		walk = func(nodes []*Node) {
			for _, node := range nodes {
				if node.Name() == "address" && !node.IsLeaf {
					for _, child := range node.Children {
						if slices.Contains(child.Keys, "10.0.0.3/24") {
							quotedChild = child
							return
						}
					}
				}
				walk(node.Children)
				if quotedChild != nil {
					return
				}
			}
		}
		walk(expanded.Children)
		if quotedChild == nil {
			t.Fatalf("expanded flat quoted address child missing")
		}
		if len(quotedChild.KeysQuoted) != len(quotedChild.Keys) ||
			len(quotedChild.KeysBracketed) != len(quotedChild.Keys) {
			t.Fatalf("quoted child masks are misaligned: keys=%q quoted=%v bracketed=%v",
				quotedChild.Keys, quotedChild.KeysQuoted, quotedChild.KeysBracketed)
		}
		if !quotedChild.KeyQuoted(0) || !quotedChild.KeyBracketed(0) {
			t.Fatalf("appended child masks = quoted:%v bracketed:%v; want true,true",
				quotedChild.KeyQuoted(0), quotedChild.KeyBracketed(0))
		}
	})
	t.Run("group bracketed plus inline single overlap keeps both", func(t *testing.T) {
		got := compile(t, famBody("inet",
			`address [ 10.0.0.1/24 10.0.0.2/24 ];`,
			`address 10.0.0.1/24;`))
		if !slices.Equal(got, []string{"10.0.0.1/24", "10.0.0.2/24"}) {
			t.Fatalf("addresses = %v, want [A B] without duplicating the shared member", got)
		}
	})
	t.Run("group bracketed plus inline single distinct keeps all three", func(t *testing.T) {
		got := compile(t, famBody("inet",
			`address [ 10.0.0.1/24 10.0.0.2/24 ];`,
			`address 10.0.0.3/24;`))
		if !slices.Equal(got, []string{"10.0.0.3/24", "10.0.0.1/24", "10.0.0.2/24"}) {
			t.Fatalf("addresses = %v, want inline first with the disjoint bracket appended", got)
		}
	})
	t.Run("packed option never unions as an address", func(t *testing.T) {
		got := compile(t, famBody("inet",
			`address 10.0.0.3/24 primary;`,
			`address [ 10.0.0.1/24 10.0.0.2/24 ];`))
		if slices.Contains(got, "primary") {
			t.Fatalf("addresses = %v, the packed option must never become an address member", got)
		}
		if !slices.Equal(got, []string{"10.0.0.1/24", "10.0.0.2/24", "10.0.0.3/24"}) {
			t.Fatalf("addresses = %v, want the packed option shape to keep existing behavior", got)
		}
	})
	t.Run("nested exclusion keeps the atomic union", func(t *testing.T) {
		text := `groups {
			H1 { interfaces { ge-0/0/0 { unit 0 { family inet { address [ 10.0.0.1/24 10.0.0.2/24 ]; } } } } }
			H2 { interfaces { ge-0/0/0 { unit 0 { family inet { address [ 10.0.0.3/24 10.0.0.4/24 ]; } } } } }
			W { interfaces { ge-0/0/0 { unit 0 { family inet { apply-groups [ H1 H2 ]; } } } } }
		}
		apply-groups W;
		interfaces { ge-0/0/0 { unit 0 { family inet { apply-groups-except H1; } } } }`
		got := compile(t, text)
		want := []string{"10.0.0.1/24", "10.0.0.2/24", "10.0.0.3/24", "10.0.0.4/24"}
		if !slices.Equal(got, want) {
			t.Fatalf("addresses = %v, want the complete uncertain union %v", got, want)
		}
	})
	t.Run("nested flat-set exclusion keeps the same union", func(t *testing.T) {
		tree := &ConfigTree{}
		for _, line := range []string{
			`set groups H1 interfaces ge-0/0/0 unit 0 family inet address [ 10.0.0.1/24 10.0.0.2/24 ]`,
			`set groups H2 interfaces ge-0/0/0 unit 0 family inet address [ 10.0.0.3/24 10.0.0.4/24 ]`,
			`set groups W interfaces ge-0/0/0 unit 0 family inet apply-groups [ H1 H2 ]`,
			`set apply-groups W`,
			`set interfaces ge-0/0/0 unit 0 family inet apply-groups-except H1`,
		} {
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		want := []string{"10.0.0.1/24", "10.0.0.2/24", "10.0.0.3/24", "10.0.0.4/24"}
		got := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].Addresses
		if !slices.Equal(got, want) {
			t.Fatalf("flat-set addresses = %v, want the same complete union %v", got, want)
		}
	})
	t.Run("flat set overlap drops the duplicate", func(t *testing.T) {
		tree := &ConfigTree{}
		for _, line := range []string{
			`set groups G interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24`,
			`set interfaces ge-0/0/0 unit 0 family inet address [ 10.0.0.1/24 10.0.0.2/24 ]`,
			`set apply-groups G`,
		} {
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		got := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].Addresses
		if !slices.Equal(got, []string{"10.0.0.1/24", "10.0.0.2/24"}) {
			t.Fatalf("flat-set addresses = %v, want [A B] without the duplicate", got)
		}
	})
}
