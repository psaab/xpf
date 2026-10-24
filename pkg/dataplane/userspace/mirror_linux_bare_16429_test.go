package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16429: a bare-physical mirror input in Linux spelling (`ge-0-0-1`) on a
// port with an untagged unit 0 must resolve to the BASE row (UnitScoped
// false, mirrors every unit), exactly like the Junos spelling
// (`ge-0/0/1`). Production rows are base-then-units (interfaces.go), and
// the untagged unit-0 row's LinuxName equals the base netdev name, so the
// unit-0 row's {vlanID:0, unitScoped:true} scope must not overwrite the
// base row's scope under the shared `ge-0-0-1` key. Pre-fix the Linux
// spelling installed as a unit-0 VID-0-only row: tagged sibling units
// were silently not mirrored while show reported the instance installed.
//
// FAIL-ON-REVERT: drop the base-row precedence in mirrors.go and the
// linux-bare cells below go back to UnitScoped:true.
func mirrorCfg16429() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}, 1: {Number: 1, VlanID: 100}}},
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{},
	}
	return cfg
}

func mirrorRows16429() []InterfaceSnapshot {
	return []InterfaceSnapshot{
		{Name: "ge-0/0/1", LinuxName: "ge-0-0-1", Ifindex: 11},
		{Name: "ge-0/0/1.0", LinuxName: "ge-0-0-1", Ifindex: 11, IsUnit: true, VLANID: 0},
		{Name: "ge-0/0/1.1", LinuxName: "ge-0-0-1.100", Ifindex: 11100, IsUnit: true, VLANID: 100, ParentIfindex: 11},
		{Name: "ge-0/0/9", LinuxName: "ge-0-0-9", Ifindex: 22},
		{Name: "ge-0/0/9.0", LinuxName: "ge-0-0-9", Ifindex: 22, IsUnit: true, VLANID: 0},
	}
}

func TestBuildMirrorConfigSnapshotsLinuxBareWithUnit0_16429(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  MirrorConfigSnapshot
	}{
		{"linux-bare", "ge-0-0-1", MirrorConfigSnapshot{IngressIfindex: 11, OutputIfindex: 22, IngressVLANID: 0, UnitScoped: false}},
		{"junos-bare", "ge-0/0/1", MirrorConfigSnapshot{IngressIfindex: 11, OutputIfindex: 22, IngressVLANID: 0, UnitScoped: false}},
		{"junos-unit0", "ge-0/0/1.0", MirrorConfigSnapshot{IngressIfindex: 11, OutputIfindex: 22, IngressVLANID: 0, UnitScoped: true, IngressUnit: 0}},
		{"linux-unit0", "ge-0-0-1.0", MirrorConfigSnapshot{IngressIfindex: 11, OutputIfindex: 22, IngressVLANID: 0, UnitScoped: true, IngressUnit: 0}},
		{"junos-tagged", "ge-0/0/1.1", MirrorConfigSnapshot{IngressIfindex: 11100, OutputIfindex: 22, IngressVLANID: 100, UnitScoped: true, IngressUnit: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mirrorCfg16429()
			cfg.ForwardingOptions.PortMirroring.Instances["span"] = &config.PortMirrorInstance{
				Name: "span", Input: []string{tc.input}, Output: "ge-0/0/9.0",
			}
			got, excl := buildMirrorConfigSnapshots(cfg, mirrorRows16429())
			if !reflect.DeepEqual(got, []MirrorConfigSnapshot{tc.want}) {
				t.Fatalf("mirror snapshots = %+v excl=%+v, want %+v", got, excl, []MirrorConfigSnapshot{tc.want})
			}
			if len(excl) != 0 {
				t.Fatalf("exclusions = %+v, want none", excl)
			}
		})
	}
}

// Both spellings in one config remain DISTINCT rows (bare + unit-0), the
// #15113 duplicate-ownership contract: the bare row matches every unit,
// the unit row is preferred for VID 0 by the Rust resolver.
func TestBuildMirrorConfigSnapshotsLinuxBareAndUnit0Distinct16429(t *testing.T) {
	cfg := mirrorCfg16429()
	cfg.ForwardingOptions.PortMirroring.Instances["span-bare"] = &config.PortMirrorInstance{
		Name: "span-bare", Input: []string{"ge-0-0-1"}, Output: "ge-0/0/9.0",
	}
	cfg.ForwardingOptions.PortMirroring.Instances["span-unit0"] = &config.PortMirrorInstance{
		Name: "span-unit0", Input: []string{"ge-0-0-1.0"}, Output: "ge-0/0/9.0",
	}
	got, excl := buildMirrorConfigSnapshots(cfg, mirrorRows16429())
	// Sorted instance order: span-bare, span-unit0.
	want := []MirrorConfigSnapshot{
		{IngressIfindex: 11, OutputIfindex: 22, IngressVLANID: 0, UnitScoped: false},
		{IngressIfindex: 11, OutputIfindex: 22, IngressVLANID: 0, UnitScoped: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mirror snapshots = %+v excl=%+v, want bare+unit0 distinct %+v", got, excl, want)
	}
	if len(excl) != 0 {
		t.Fatalf("exclusions = %+v, want none", excl)
	}
}

// End-to-end through the real interface-row builder: set commands ->
// strict CompileConfig -> buildInterfaceSnapshots -> mirror builder. The
// Linux-spelled bare input must install unscoped, like the Junos spelling.
func TestMirrorLinuxBareE2E16429(t *testing.T) {
	links := map[string]int{"ge-0-0-1": 11, "ge-0-0-1.100": 11100, "ge-0-0-9": 22}
	for _, input := range []string{"ge-0-0-1", "ge-0/0/1"} {
		t.Run(input, func(t *testing.T) {
			cfg := compileWithStubbedLinks6722(t, []string{
				"set interfaces ge-0/0/1 flexible-vlan-tagging",
				"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
				"set interfaces ge-0/0/1 unit 1 vlan-id 100",
				"set interfaces ge-0/0/1 unit 1 family inet address 10.0.100.1/24",
				"set interfaces ge-0/0/9 unit 0 family inet address 10.0.9.1/24",
				"set forwarding-options port-mirroring instance span input ingress interface " + input,
				"set forwarding-options port-mirroring instance span output interface ge-0/0/9.0",
			}, links, map[string]string{}, false)
			interfaces := buildInterfaceSnapshots(cfg)
			// Preconditions: the production row shape the defect needs —
			// a base row and an untagged unit-0 row sharing ifindex 11,
			// plus a tagged unit-1 row. Without these the cell is vacuous.
			var base, unit0, unit1 bool
			for _, s := range interfaces {
				switch s.Name {
				case "ge-0/0/1":
					base = !s.IsUnit && s.LinuxName == "ge-0-0-1" && s.Ifindex == 11
				case "ge-0/0/1.0":
					unit0 = s.IsUnit && s.LinuxName == "ge-0-0-1" && s.Ifindex == 11 && s.VLANID == 0
				case "ge-0/0/1.1":
					unit1 = s.IsUnit && s.Ifindex == 11100 && s.VLANID == 100
				}
			}
			if !base || !unit0 || !unit1 {
				t.Fatalf("fixture rows = %+v, want base+unit0 on ifindex 11 and unit1 VID 100", interfaces)
			}
			got, excl := buildMirrorConfigSnapshots(cfg, interfaces)
			want := []MirrorConfigSnapshot{
				{IngressIfindex: 11, OutputIfindex: 22, IngressVLANID: 0, UnitScoped: false},
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("mirror snapshots = %+v excl=%+v, want unscoped bare row %+v", got, excl, want)
			}
			if len(excl) != 0 {
				t.Fatalf("exclusions = %+v, want none", excl)
			}
		})
	}
}
