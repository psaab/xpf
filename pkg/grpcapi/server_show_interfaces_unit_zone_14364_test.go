package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14364: the gRPC ShowText twins of the #5325 CLI fix never landed.
// showVLANs keyed ifZone by the raw zone-member string ("ge-0/0/9.50",
// "eth0.0") and queried it with the bare base name (ifc.Name), blanking
// the Zone column (and the #12899 quarantine qualifier) for every
// unit-qualified binding. showInterfacesExtensive / showInterfacesDetail
// keyed ifZoneMap by the raw member and queried it with the bare kernel
// name (attrs.Name), so a "ge-0/0/1.0" binding never rendered its
// `Security zone:` line either.
//
// Fixture mirrors the issue's decisive check:
//   - ge-0/0/9 unit 50 (VLAN 50) bound as "ge-0/0/9.50" to trust
//     (showVLANs per-unit row),
//   - a real host kernel link bound as "<name>.0" to a quarantined zone
//     (detail/extensive physical rows render the zone + qualifier),
//   - plus a ".50"-only bound real link as the negative control for
//     detail/extensive: a non-zero unit must NOT be attributed to the
//     physical interface row (that would misattribute a VLAN unit).

func unitZone14364VLANRow(t *testing.T, out, iface, unit string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == iface && f[1] == unit {
			return line
		}
	}
	t.Fatalf("no vlan row for %s unit %s:\n%s", iface, unit, out)
	return ""
}

func TestShowVLANsUnitQualifiedZone14364(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"ge-0/0/9.50"}},
			"z174":  {Name: "z174", Interfaces: []string{"ge-0/0/0"}},
			"z214":  {Name: "z214", Interfaces: []string{"ge-0/0/1.0"}},
		}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/9": {Name: "ge-0/0/9", VlanTagging: true, Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50},
		}},
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, VlanID: 10},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, VlanID: 20},
		}},
	}
	var buf strings.Builder
	(&Server{}).showVLANs(cfg, &buf)
	out := buf.String()

	// Unit-qualified binding: the unit-50 row must name trust.
	row50 := unitZone14364VLANRow(t, out, "ge-0/0/9", "50")
	if !strings.Contains(row50, "trust") {
		t.Fatalf("show vlans Zone blank for unit-qualified ge-0/0/9.50 (#14364): %q\n%s", row50, out)
	}
	// Unit-0-qualified quarantined binding: zone + qualifier.
	rowQ := unitZone14364VLANRow(t, out, "ge-0/0/1", "0")
	if !strings.Contains(rowQ, "z214") || !strings.Contains(rowQ, config.ZoneQuarantineInterfacesQualifier) {
		t.Fatalf("show vlans quarantined unit-0 row missing zone/qualifier (#14364): %q\n%s", rowQ, out)
	}
	// Bare binding control: still resolves, and the survivor is not qualified.
	rowBare := unitZone14364VLANRow(t, out, "ge-0/0/0", "0")
	if !strings.Contains(rowBare, "z174") {
		t.Fatalf("show vlans bare binding regressed: %q\n%s", rowBare, out)
	}
	if strings.Contains(rowBare, config.ZoneQuarantineInterfacesQualifier) {
		t.Fatalf("show vlans survivor falsely qualified: %q\n%s", rowBare, out)
	}
}

// physicalBlock14364 returns the output block for one physical interface
// (from its "Physical interface: <name>," header to the next header).
func physicalBlock14364(out, name string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Physical interface: ") {
			if in {
				break
			}
			in = strings.HasPrefix(line, "Physical interface: "+name+",")
			if !in {
				continue
			}
		}
		if in {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func TestShowInterfacesDetailExtensiveUnit0Zone14364(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	realIf := firstNonLoopbackLink(t)
	if realIf == "" {
		t.Skip("no non-loopback kernel link on this host")
	}
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"z174": {Name: "z174", Interfaces: []string{realIf + ".50"}},
			"z214": {Name: "z214", Interfaces: []string{realIf + ".0"}},
		}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		realIf: {Name: realIf, Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0},
			50: {Number: 50, VlanID: 50},
		}},
	}

	var buf strings.Builder
	if err := (&Server{}).showInterfacesDetail(cfg, "", &buf); err != nil {
		t.Fatalf("showInterfacesDetail: %v", err)
	}
	detail := physicalBlock14364(buf.String(), realIf)
	if detail == "" {
		t.Fatalf("detail output missing physical block for %q:\n%s", realIf, buf.String())
	}
	if !strings.Contains(detail, "Security zone: z214") ||
		!strings.Contains(detail, config.ZoneQuarantineInterfacesQualifier) {
		t.Fatalf("detail missing unit-0 zone/qualifier for %s.0 (#14364):\n%s", realIf, detail)
	}
	// A .50-only attribution must not leak onto the physical row: z174 is
	// bound only via unit 50, so its name must not appear as this row's zone.
	if strings.Contains(detail, "Security zone: z174") {
		t.Fatalf("detail misattributed unit-50 zone z174 to physical row:\n%s", detail)
	}

	buf.Reset()
	if err := (&Server{}).showInterfacesExtensive(cfg, "", &buf); err != nil {
		t.Fatalf("showInterfacesExtensive: %v", err)
	}
	ext := physicalBlock14364(buf.String(), realIf)
	if ext == "" {
		t.Fatalf("extensive output missing physical block for %q:\n%s", realIf, buf.String())
	}
	if !strings.Contains(ext, "Security zone: z214") ||
		!strings.Contains(ext, config.ZoneQuarantineInterfacesQualifier) {
		t.Fatalf("extensive missing unit-0 zone/qualifier for %s.0 (#14364):\n%s", realIf, ext)
	}
	if strings.Contains(ext, "Security zone: z174") {
		t.Fatalf("extensive misattributed unit-50 zone z174 to physical row:\n%s", ext)
	}
}
