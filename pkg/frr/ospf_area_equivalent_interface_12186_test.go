package frr

// #12186: equivalent-area OSPF interface fragments UNION; they must not
// first-win. Distinct area-ID spellings of one 32-bit area ("0" vs
// "0.0.0.0"), and authored interface aliases resolving to one Linux device
// ("ge-0/0/1.0", "ge-0-0-1.0", "ge-0/0/1", "ge-0-0-1"), can leave multiple
// model fragments for one FRR interface context. Disjoint settings from every
// fragment must render; on a true value conflict the tolerant renderer keeps
// the first present value per field and warns (strict compilation rejects).
//
// These cells assert the UNION. Absence assertions below cover only
// conflict first-wins, dropped different-area fragments, and negated
// passive variants — never disjoint settings.

import (
	"bytes"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileTree12186(t *testing.T, strict bool, cmds ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	all := append([]string{"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24"}, cmds...)
	for _, cmd := range all {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if strict {
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		return cfg
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

func renderManaged12186(cfg *config.Config) string {
	fc := &FullConfig{OSPF: cfg.Protocols.OSPF, OSPFv3: cfg.Protocols.OSPFv3, IfNameResolver: cfg.ResolveKernelIfName}
	return New().buildManagedSection(fc)
}

func countInterfaceBlocks12186(out, name string) int {
	return strings.Count(out, "\ninterface "+name+"\n")
}

func captureSlog12186() (*bytes.Buffer, func()) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	return &logs, func() { slog.SetDefault(previous) }
}

func orderName12186(costFirst bool) string {
	if costFirst {
		return "cost-first"
	}
	return "settings-first"
}

// A cost fragment plus a settings fragment must union across equivalent-area
// orderings, v2 and v3: auth, hello/dead/retransmit, priority 0, p2p (v2),
// and BFD (v2+v3) are all retained in exactly one interface context, the
// first raw area-ID spelling activates the interface, and rendering never
// mutates its inputs.
func TestOSPFAreaEquivalentUnionAcrossOrderings12186(t *testing.T) {
	for _, ids := range [][2]string{{"0", "0.0.0.0"}, {"0.0.0.0", "0"}} {
		for _, costFirst := range []bool{true, false} {
			name := ids[0] + "-then-" + ids[1] + "-" + orderName12186(costFirst)
			t.Run("ospfv2 "+name, func(t *testing.T) {
				logs, restore := captureSlog12186()
				defer restore()
				costFrag := &config.OSPFInterface{Name: "eth0", Cost: 10, BFDInterval: 100}
				settingsFrag := &config.OSPFInterface{
					Name:     "eth0",
					AuthType: "simple", AuthKey: config.NewSecret("union-pw"),
					HelloInterval: 5, DeadInterval: 20, RetransmitInt: 7,
					HasPriority: true, // Priority 0 ("never DR") is set, not unset.
					NetworkType: "point-to-point",
					BFD:         true, BFDMultiplier: 4,
				}
				first, second := costFrag, settingsFrag
				if !costFirst {
					first, second = second, first
				}
				beforeFirst, beforeSecond := *first, *second
				ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{
					{ID: ids[0], Interfaces: []*config.OSPFInterface{first}},
					{ID: ids[1], Interfaces: []*config.OSPFInterface{second}},
				}}
				got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
				if n := countInterfaceBlocks12186(got, "eth0"); n != 1 {
					t.Fatalf("rendered %d interface blocks; want exactly one unioned context:\n%s", n, got)
				}
				for _, want := range []string{
					" ip ospf cost 10\n",
					" ip ospf authentication\n",
					" ip ospf authentication-key union-pw\n",
					" ip ospf hello-interval 5\n",
					" ip ospf dead-interval 20\n",
					" ip ospf retransmit-interval 7\n",
					" ip ospf priority 0\n",
					" ip ospf network point-to-point\n",
					" ip ospf bfd profile xpf-100-4\n",
					" ip ospf area " + ids[0] + "\n",
				} {
					if !strings.Contains(got, want) {
						t.Errorf("union lost %q:\n%s", want, got)
					}
				}
				if strings.Contains(logs.String(), "conflicting OSPF interface settings") {
					t.Errorf("disjoint fragments must merge silently, got warning: %s", logs.String())
				}
				if !reflect.DeepEqual(*first, beforeFirst) || !reflect.DeepEqual(*second, beforeSecond) {
					t.Errorf("render mutated its input fragments: %+v %+v", first, second)
				}
			})

			t.Run("ospfv3 "+name, func(t *testing.T) {
				logs, restore := captureSlog12186()
				defer restore()
				costFrag := &config.OSPFv3Interface{Name: "eth0", Cost: 10, BFDInterval: 100}
				settingsFrag := &config.OSPFv3Interface{
					Name: "eth0", Passive: true,
					HelloInterval: 5, DeadInterval: 20, RetransmitInt: 7,
					HasPriority: true, // Priority 0 ("never DR") is set, not unset.
					BFD:         true, BFDMultiplier: 4,
				}
				first, second := costFrag, settingsFrag
				if !costFirst {
					first, second = second, first
				}
				beforeFirst, beforeSecond := *first, *second
				ospf := &config.OSPFv3Config{Areas: []*config.OSPFv3Area{
					{ID: ids[0], Interfaces: []*config.OSPFv3Interface{first}},
					{ID: ids[1], Interfaces: []*config.OSPFv3Interface{second}},
				}}
				got := New().generateProtocols(nil, ospf, nil, nil, nil, "", 0, nil, nil)
				if n := countInterfaceBlocks12186(got, "eth0"); n != 1 {
					t.Fatalf("rendered %d interface blocks; want exactly one unioned context:\n%s", n, got)
				}
				for _, want := range []string{
					" ipv6 ospf6 area " + ids[0] + "\n",
					" ipv6 ospf6 passive\n",
					" ipv6 ospf6 cost 10\n",
					" ipv6 ospf6 hello-interval 5\n",
					" ipv6 ospf6 dead-interval 20\n",
					" ipv6 ospf6 retransmit-interval 7\n",
					" ipv6 ospf6 priority 0\n",
					" ipv6 ospf6 bfd profile xpf-100-4\n",
				} {
					if !strings.Contains(got, want) {
						t.Errorf("union lost %q:\n%s", want, got)
					}
				}
				if strings.Contains(logs.String(), "conflicting OSPF interface settings") {
					t.Errorf("disjoint fragments must merge silently, got warning: %s", logs.String())
				}
				if !reflect.DeepEqual(*first, beforeFirst) || !reflect.DeepEqual(*second, beforeSecond) {
					t.Errorf("render mutated its input fragments: %+v %+v", first, second)
				}
			})
		}
	}
}

// Duplicate passive directives must stay deduplicated: without the
// directiveEmitted guard, two same-area fragments both carrying the flag
// would emit the directive twice.
func TestOSPFDuplicatePassiveDirectiveGuard12186(t *testing.T) {
	for _, ids := range [][2]string{{"0", "0.0.0.0"}, {"0.0.0.0", "0"}} {
		name := ids[0] + "-then-" + ids[1]
		t.Run("both-passive "+name, func(t *testing.T) {
			ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: ids[0], Interfaces: []*config.OSPFInterface{{Name: "eth0", Cost: 10, Passive: true}}},
				{ID: ids[1], Interfaces: []*config.OSPFInterface{{Name: "eth0", HelloInterval: 5, Passive: true}}},
			}}
			got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
			if n := strings.Count(got, " passive-interface eth0\n"); n != 1 {
				t.Fatalf("rendered %d passive directives; want exactly one:\n%s", n, got)
			}
			if n := strings.Count(got, " no passive-interface eth0\n"); n != 0 {
				t.Fatalf("rendered %d negated passive directives; want none:\n%s", n, got)
			}
			if !strings.Contains(got, " ip ospf cost 10\n") || !strings.Contains(got, " ip ospf hello-interval 5\n") {
				t.Errorf("disjoint settings lost alongside the dedup:\n%s", got)
			}
		})

		t.Run("passive-default-both-NoPassive "+name, func(t *testing.T) {
			ospf := &config.OSPFConfig{PassiveDefault: true, Areas: []*config.OSPFArea{
				{ID: ids[0], Interfaces: []*config.OSPFInterface{{Name: "eth0", Cost: 10, NoPassive: true}}},
				{ID: ids[1], Interfaces: []*config.OSPFInterface{{Name: "eth0", HelloInterval: 5, NoPassive: true}}},
			}}
			got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
			if n := strings.Count(got, " no passive-interface eth0\n"); n != 1 {
				t.Fatalf("rendered %d negated passive directives; want exactly one:\n%s", n, got)
			}
			if n := strings.Count(got, "\n passive-interface eth0\n"); n != 0 {
				t.Fatalf("rendered %d plain passive directives under passive-default; want none:\n%s", n, got)
			}
			if !strings.Contains(got, " ip ospf cost 10\n") || !strings.Contains(got, " ip ospf hello-interval 5\n") {
				t.Errorf("disjoint settings lost alongside the dedup:\n%s", got)
			}
		})
	}
}

// Strict compile through buildManagedSection: a cost fragment plus an MD5
// fragment unions whether the areas share one raw spelling or two
// equivalent spellings.
func TestOSPFStrictCompileCostPlusMD512186(t *testing.T) {
	for _, areas := range [][2]string{{"0", "0.0.0.0"}, {"0.0.0.0", "0"}, {"0", "0"}} {
		t.Run("areas "+areas[0]+"-then-"+areas[1], func(t *testing.T) {
			cfg := compileTree12186(t, true,
				"set protocols ospf area "+areas[0]+" interface ge-0/0/1.0 cost 10",
				"set protocols ospf area "+areas[1]+" interface ge-0/0/1.0 authentication md5 7 key auth-key-12186",
			)
			got := renderManaged12186(cfg)
			if n := countInterfaceBlocks12186(got, "ge-0-0-1"); n != 1 {
				t.Fatalf("rendered %d ge-0-0-1 blocks; want exactly one:\n%s", n, got)
			}
			for _, want := range []string{
				" ip ospf cost 10\n",
				" ip ospf authentication message-digest\n",
				" ip ospf message-digest-key 7 md5 auth-key-12186\n",
				" ip ospf area " + areas[0] + "\n",
			} {
				if !strings.Contains(got, want) {
					t.Errorf("union lost %q:\n%s", want, got)
				}
			}
			if strings.Contains(got, "ge-0/0/1") {
				t.Errorf("raw slash spelling leaked into the managed section:\n%s", got)
			}
		})
	}
}

// Strict compile through buildManagedSection: every authored alias spelling
// of one unit resolves to the same kernel device and unions with the
// canonical fragment, in one raw area and across equivalent areas.
func TestOSPFStrictCompileAliasSpellings12186(t *testing.T) {
	sanitize := strings.NewReplacer("/", "_")
	for _, alias := range []string{"ge-0/0/1.0", "ge-0-0-1.0", "ge-0/0/1", "ge-0-0-1"} {
		for _, shape := range []struct {
			name  string
			areas [2]string
		}{
			{"same-area", [2]string{"0", "0"}},
			{"equivalent-areas", [2]string{"0", "0.0.0.0"}},
		} {
			t.Run(sanitize.Replace(alias)+"-"+shape.name, func(t *testing.T) {
				cfg := compileTree12186(t, true,
					"set protocols ospf area "+shape.areas[0]+" interface ge-0/0/1.0 cost 10",
					"set protocols ospf area "+shape.areas[1]+" interface "+alias+" authentication md5 7 key alias-key-12186",
				)
				got := renderManaged12186(cfg)
				if n := countInterfaceBlocks12186(got, "ge-0-0-1"); n != 1 {
					t.Fatalf("alias %q rendered %d ge-0-0-1 blocks; want exactly one:\n%s", alias, n, got)
				}
				for _, want := range []string{
					" ip ospf cost 10\n",
					" ip ospf authentication message-digest\n",
					" ip ospf message-digest-key 7 md5 alias-key-12186\n",
					" ip ospf area " + shape.areas[0] + "\n",
				} {
					if !strings.Contains(got, want) {
						t.Errorf("alias %q union lost %q:\n%s", alias, want, got)
					}
				}
				if strings.Contains(got, "ge-0/0/1") {
					t.Errorf("raw slash spelling leaked into the managed section:\n%s", got)
				}
			})
		}
	}
}

// Strict compile through buildManagedSection: two MD5 key IDs on one
// interface — a rollover — must both render, in one raw area and across
// equivalent areas. Asserts rendered output only.
func TestOSPFStrictCompileMD5Rollover12186(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
		area string
	}{
		{"same-area", []string{
			"set protocols ospf area 0 interface ge-0/0/1.0 authentication md5 1 key rollover-1st",
			"set protocols ospf area 0 interface ge-0/0/1.0 authentication md5 2 key rollover-2nd",
		}, "0"},
		{"equivalent-areas", []string{
			"set protocols ospf area 0 interface ge-0/0/1.0 authentication md5 1 key rollover-1st",
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 2 key rollover-2nd",
		}, "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileTree12186(t, true, tc.cmds...)
			got := renderManaged12186(cfg)
			if n := countInterfaceBlocks12186(got, "ge-0-0-1"); n != 1 {
				t.Fatalf("rendered %d ge-0-0-1 blocks; want exactly one:\n%s", n, got)
			}
			for _, want := range []string{
				" ip ospf message-digest-key 1 md5 rollover-1st\n",
				" ip ospf message-digest-key 2 md5 rollover-2nd\n",
				" ip ospf area " + tc.area + "\n",
			} {
				if !strings.Contains(got, want) {
					t.Errorf("rollover lost %q:\n%s", want, got)
				}
			}
			if n := strings.Count(got, " ip ospf authentication message-digest\n"); n != 1 {
				t.Errorf("auth mode line rendered %d times; want once:\n%s", n, got)
			}
		})
	}
}

// Strict compile through buildManagedSection: group-inherited MD5 unions
// with inline settings, and a group key plus an inline key roll over.
func TestOSPFStrictCompileApplyGroupsMD512186(t *testing.T) {
	t.Run("group-md5-plus-inline-cost", func(t *testing.T) {
		cfg := compileTree12186(t, true,
			"set groups OSPF-MD5-12186 protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 7 key group-key-12186",
			"set apply-groups OSPF-MD5-12186",
			"set protocols ospf area 0 interface ge-0/0/1.0 cost 10",
		)
		got := renderManaged12186(cfg)
		if n := countInterfaceBlocks12186(got, "ge-0-0-1"); n != 1 {
			t.Fatalf("rendered %d ge-0-0-1 blocks; want exactly one:\n%s", n, got)
		}
		for _, want := range []string{
			" ip ospf cost 10\n",
			" ip ospf authentication message-digest\n",
			" ip ospf message-digest-key 7 md5 group-key-12186\n",
			" ip ospf area 0\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("group/inline union lost %q:\n%s", want, got)
			}
		}
	})

	t.Run("group-md5-plus-inline-md5-rollover", func(t *testing.T) {
		cfg := compileTree12186(t, true,
			"set groups OSPF-MD5-12186 protocols ospf area 0 interface ge-0/0/1.0 authentication md5 1 key group-1st-12186",
			"set apply-groups OSPF-MD5-12186",
			"set protocols ospf area 0 interface ge-0/0/1.0 authentication md5 2 key inline-2nd-12186",
		)
		got := renderManaged12186(cfg)
		if n := countInterfaceBlocks12186(got, "ge-0-0-1"); n != 1 {
			t.Fatalf("rendered %d ge-0-0-1 blocks; want exactly one:\n%s", n, got)
		}
		for _, want := range []string{
			" ip ospf message-digest-key 1 md5 group-1st-12186\n",
			" ip ospf message-digest-key 2 md5 inline-2nd-12186\n",
			" ip ospf area 0\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("group/inline rollover lost %q:\n%s", want, got)
			}
		}
		if n := strings.Count(got, " ip ospf authentication message-digest\n"); n != 1 {
			t.Errorf("auth mode line rendered %d times; want once:\n%s", n, got)
		}
	})
}

// The generated point-to-point fallback line must survive: the interface
// carries one settings block plus one OSPF block, and a dropped
// different-area fragment must neither leak its network type nor suppress
// the fallback.
func TestOSPFNetworkFallbackPointToPoint12186(t *testing.T) {
	t.Run("direct single fragment", func(t *testing.T) {
		ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{
			{ID: "0", Interfaces: []*config.OSPFInterface{{Name: "eth0", Cost: 10}}},
		}}
		fc := &FullConfig{OSPF: ospf, InterfacePointToPoint: map[string]bool{"eth0": true}}
		got := New().buildManagedSection(fc)
		if n := countInterfaceBlocks12186(got, "eth0"); n != 2 {
			t.Fatalf("want the settings block plus the OSPF block (2), got %d:\n%s", n, got)
		}
		if n := strings.Count(got, " ip ospf network "); n != 1 || !strings.Contains(got, " ip ospf network point-to-point\n") {
			t.Errorf("fallback p2p line must render exactly once, network lines = %d:\n%s", n, got)
		}
		if n := strings.Count(got, " ip ospf area "); n != 1 || !strings.Contains(got, " ip ospf area 0\n") {
			t.Errorf("want exactly one OSPF activation (area 0), got %d:\n%s", n, got)
		}
	})

	t.Run("direct dropped different-area fragment", func(t *testing.T) {
		logs, restore := captureSlog12186()
		defer restore()
		ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{
			{ID: "0", Interfaces: []*config.OSPFInterface{{Name: "eth0", Cost: 10}}},
			{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "eth0", NetworkType: "broadcast"}}},
		}}
		fc := &FullConfig{OSPF: ospf, InterfacePointToPoint: map[string]bool{"eth0": true}}
		got := New().buildManagedSection(fc)
		if n := strings.Count(got, " ip ospf network "); n != 1 || !strings.Contains(got, " ip ospf network point-to-point\n") {
			t.Errorf("dropped fragment suppressed the fallback p2p line, network lines = %d:\n%s", n, got)
		}
		if strings.Contains(got, "ip ospf network broadcast") {
			t.Errorf("dropped different-area setting leaked:\n%s", got)
		}
		if n := strings.Count(got, " ip ospf area "); n != 1 || !strings.Contains(got, " ip ospf area 0\n") {
			t.Errorf("want exactly one OSPF activation (area 0), got %d:\n%s", n, got)
		}
		if !strings.Contains(logs.String(), "dropping an OSPF interface assigned to multiple areas") ||
			!strings.Contains(logs.String(), "dropped_area=0.0.0.1") {
			t.Errorf("the different-area fragment must be dropped with a warning: %s", logs.String())
		}
	})

	t.Run("lenient compile dropped different-area fragment", func(t *testing.T) {
		logs, restore := captureSlog12186()
		defer restore()
		cfg := compileTree12186(t, false,
			"set protocols ospf area 0 interface ge-0/0/1.0 cost 10",
			"set protocols ospf area 0.0.0.1 interface ge-0/0/1.0 interface-type p2p",
		)
		fc := &FullConfig{OSPF: cfg.Protocols.OSPF, IfNameResolver: cfg.ResolveKernelIfName, InterfacePointToPoint: map[string]bool{"ge-0-0-1": true}}
		got := New().buildManagedSection(fc)
		if n := strings.Count(got, " ip ospf network "); n != 1 || !strings.Contains(got, " ip ospf network point-to-point\n") {
			t.Errorf("dropped fragment suppressed the fallback p2p line, network lines = %d:\n%s", n, got)
		}
		if n := strings.Count(got, " ip ospf area "); n != 1 || !strings.Contains(got, " ip ospf area 0\n") {
			t.Errorf("want exactly one OSPF activation (area 0), got %d:\n%s", n, got)
		}
		if !strings.Contains(logs.String(), "dropping an OSPF interface assigned to multiple areas") ||
			!strings.Contains(logs.String(), "dropped_area=0.0.0.1") {
			t.Errorf("the different-area fragment must be dropped with a warning: %s", logs.String())
		}
	})
}

// Tolerant conflicts keep the first present value per field and warn —
// never silently. MD5 keys union by ID; only a same-ID secret mismatch
// conflicts.
func TestOSPFTolerantConflictRetainsFirstPresent12186(t *testing.T) {
	for _, swap := range []bool{false, true} {
		name := map[bool]string{false: "first-cost-10", true: "first-cost-20"}[swap]
		t.Run("ospfv2 "+name, func(t *testing.T) {
			logs, restore := captureSlog12186()
			defer restore()
			a := &config.OSPFInterface{Name: "eth0", Cost: 10, HelloInterval: 5, AuthType: "simple", AuthKey: config.NewSecret("first-pw")}
			b := &config.OSPFInterface{Name: "eth0", Cost: 20, HelloInterval: 9, AuthType: "simple", AuthKey: config.NewSecret("secondpw")}
			want, absent := a, b
			if swap {
				want, absent = b, a
			}
			ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: "0", Interfaces: []*config.OSPFInterface{want}},
				{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{absent}},
			}}
			got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
			if n := countInterfaceBlocks12186(got, "eth0"); n != 1 {
				t.Fatalf("rendered %d interface blocks; want exactly one:\n%s", n, got)
			}
			for _, wantLine := range []string{
				" ip ospf cost " + strconv.Itoa(want.Cost) + "\n",
				" ip ospf hello-interval " + strconv.Itoa(want.HelloInterval) + "\n",
				" ip ospf authentication-key " + want.AuthKey.Reveal() + "\n",
			} {
				if !strings.Contains(got, wantLine) {
					t.Errorf("first-present value lost: %q:\n%s", wantLine, got)
				}
			}
			for _, absentLine := range []string{
				" ip ospf cost " + strconv.Itoa(absent.Cost) + "\n",
				" ip ospf hello-interval " + strconv.Itoa(absent.HelloInterval) + "\n",
				absent.AuthKey.Reveal(),
			} {
				if strings.Contains(got, absentLine) {
					t.Errorf("conflicting later value leaked: %q:\n%s", absentLine, got)
				}
			}
			assertConflictWarned12186(t, logs.String(), "OSPF", []string{"cost", "hello-interval", "authentication simple-password"})
			for _, secret := range []string{"first-pw", "secondpw"} {
				if strings.Contains(logs.String(), secret) {
					t.Errorf("conflict warning exposed a secret: %s", logs.String())
				}
			}
		})

		t.Run("ospfv3 "+name, func(t *testing.T) {
			logs, restore := captureSlog12186()
			defer restore()
			a := &config.OSPFv3Interface{Name: "eth0", Cost: 10}
			b := &config.OSPFv3Interface{Name: "eth0", Cost: 20}
			want, absent := a, b
			if swap {
				want, absent = b, a
			}
			ospf := &config.OSPFv3Config{Areas: []*config.OSPFv3Area{
				{ID: "0", Interfaces: []*config.OSPFv3Interface{want}},
				{ID: "0.0.0.0", Interfaces: []*config.OSPFv3Interface{absent}},
			}}
			got := New().generateProtocols(nil, ospf, nil, nil, nil, "", 0, nil, nil)
			if n := countInterfaceBlocks12186(got, "eth0"); n != 1 {
				t.Fatalf("rendered %d interface blocks; want exactly one:\n%s", n, got)
			}
			if wantLine := " ipv6 ospf6 cost " + strconv.Itoa(want.Cost) + "\n"; !strings.Contains(got, wantLine) {
				t.Errorf("first-present value lost: %q:\n%s", wantLine, got)
			}
			if absentLine := " ipv6 ospf6 cost " + strconv.Itoa(absent.Cost) + "\n"; strings.Contains(got, absentLine) {
				t.Errorf("conflicting later value leaked: %q:\n%s", absentLine, got)
			}
			assertConflictWarned12186(t, logs.String(), "OSPFv3", []string{"cost"})
		})

		t.Run("ospfv2 md5-same-id "+name, func(t *testing.T) {
			logs, restore := captureSlog12186()
			defer restore()
			a := &config.OSPFInterface{Name: "eth0", AuthType: "md5", AuthKeyID: 7, AuthKey: config.NewSecret("md5-1st-12186")}
			b := &config.OSPFInterface{Name: "eth0", AuthType: "md5", AuthKeyID: 7, AuthKey: config.NewSecret("md5-2nd-12186")}
			want, absent := a, b
			if swap {
				want, absent = b, a
			}
			ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: "0", Interfaces: []*config.OSPFInterface{want}},
				{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{absent}},
			}}
			got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
			if n := countInterfaceBlocks12186(got, "eth0"); n != 1 {
				t.Fatalf("rendered %d interface blocks; want exactly one:\n%s", n, got)
			}
			if wantLine := " ip ospf message-digest-key 7 md5 " + want.AuthKey.Reveal() + "\n"; !strings.Contains(got, wantLine) {
				t.Errorf("first-present key lost: %q:\n%s", wantLine, got)
			}
			if strings.Contains(got, absent.AuthKey.Reveal()) {
				t.Errorf("conflicting later key leaked:\n%s", got)
			}
			assertConflictWarned12186(t, logs.String(), "OSPF", []string{"authentication md5 key"})
			for _, secret := range []string{"md5-1st-12186", "md5-2nd-12186"} {
				if strings.Contains(logs.String(), secret) {
					t.Errorf("conflict warning exposed a secret: %s", logs.String())
				}
			}
		})
		t.Run("ospfv2 incompatible-auth-type "+name, func(t *testing.T) {
			logs, restore := captureSlog12186()
			defer restore()
			md5 := &config.OSPFInterface{Name: "eth0", AuthType: "md5", AuthKeyID: 11, AuthKey: config.NewSecret("md5-auth-1st")}
			simple := &config.OSPFInterface{Name: "eth0", AuthType: "simple", AuthKey: config.NewSecret("simplepw")}
			first, later := md5, simple
			if swap {
				first, later = simple, md5
			}
			ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: "0", Interfaces: []*config.OSPFInterface{first}},
				{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{later}},
			}}
			got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
			if n := countInterfaceBlocks12186(got, "eth0"); n != 1 {
				t.Fatalf("rendered %d interface blocks; want exactly one:\n%s", n, got)
			}
			if first.AuthType == "md5" {
				if !strings.Contains(got, " ip ospf message-digest-key 11 md5 md5-auth-1st\n") ||
					strings.Contains(got, " ip ospf authentication-key ") ||
					strings.Contains(got, "simplepw") {
					t.Errorf("simple-password key crossed into first-present MD5 auth:\n%s", got)
				}
			} else {
				if !strings.Contains(got, " ip ospf authentication-key simplepw\n") ||
					strings.Contains(got, " ip ospf authentication message-digest\n") ||
					strings.Contains(got, " ip ospf message-digest-key ") ||
					strings.Contains(got, "md5-auth-1st") {
					t.Errorf("MD5 key crossed into first-present simple auth:\n%s", got)
				}
			}
			assertConflictWarned12186(t, logs.String(), "OSPF", []string{"authentication-type"})
			for _, secret := range []string{"md5-auth-1st", "simplepw"} {
				if strings.Contains(logs.String(), secret) {
					t.Errorf("conflict warning exposed a secret: %s", logs.String())
				}
			}
		})
	}

	t.Run("ospfv2 md5-distinct-ids union silently", func(t *testing.T) {
		logs, restore := captureSlog12186()
		defer restore()
		ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{
			{ID: "0", Interfaces: []*config.OSPFInterface{{Name: "eth0", AuthType: "md5", AuthKeyID: 1, AuthKey: config.NewSecret("md5-old-12186")}}},
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "eth0", AuthType: "md5", AuthKeyID: 2, AuthKey: config.NewSecret("md5-new-12186")}}},
		}}
		got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
		if n := countInterfaceBlocks12186(got, "eth0"); n != 1 {
			t.Fatalf("rendered %d interface blocks; want exactly one:\n%s", n, got)
		}
		for _, want := range []string{
			" ip ospf authentication message-digest\n",
			" ip ospf message-digest-key 1 md5 md5-old-12186\n",
			" ip ospf message-digest-key 2 md5 md5-new-12186\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("distinct-ID keys must both render, lost %q:\n%s", want, got)
			}
		}
		if strings.Contains(logs.String(), "conflicting OSPF interface settings") {
			t.Errorf("distinct key IDs must union silently, got warning: %s", logs.String())
		}
	})
}

func assertConflictWarned12186(t *testing.T, logs, protocol string, fields []string) {
	t.Helper()
	if !strings.Contains(logs, "conflicting OSPF interface settings") {
		t.Errorf("conflict must warn, not stay silent: %s", logs)
	}
	if !strings.Contains(logs, "protocol="+protocol) || !strings.Contains(logs, "interface=eth0") {
		t.Errorf("conflict warning must scope protocol and interface: %s", logs)
	}
	for _, field := range fields {
		if !strings.Contains(logs, field) {
			t.Errorf("conflict warning must name %q: %s", field, logs)
		}
	}
}
