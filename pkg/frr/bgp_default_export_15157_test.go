package frr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const bgpDefaultExportNameForTest15157 = "xpf-default-export-xpf-chain"

// #15157 (B08-02): routes one neighbour's export policy originates
// (#14586) enter the SHARED BGP RIB. A neighbour whose export chain is
// absent, or ends without a final reject, must not advertise them:
// Junos default export permits only active BGP routes. Fix direction:
// (1) every neighbour/AF with an empty effective export in an
// originating instance attaches the generated default-export map
// (permit source-protocol bgp, deny rest); (2) the #2998 trailing
// permit of export maps (single and composed) becomes
// deny-non-BGP / permit-BGP; import maps keep the plain permit.
//
// RED evidence: on origin/master these tests fail — the no-export peer
// renders NO `route-map ... out` at all (absent attachment permits
// under `no bgp ebgp-requires-policy`) and the exporting peer's EXP
// map ends in a plain `permit` tail.

func routeMapBlock15157(rendered, name string) string {
	return routeMapBlock11447(rendered, name)
}

// leakFixture15157: EXP (from protocol static, accept, NO default)
// is neighbour A's own export; neighbour C has NO export at all.
// Neighbour B carries a composed export [TAG EXP2] whose members
// fall off (TAG only sets a community, EXP2 only matches a prefix).
// D carries an import using EXP so the import-direction control can
// prove EXP-as-import is untouched when it is not also an export...
// (EXP is also an export here, so a separate IMP fixture below pins
// the pure-import case.)
func leakPO15157() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocols: []string{"static"}, PrefixList: []string{"adv"}, Action: "accept"},
				},
			},
			"TAG": {
				Name: "TAG",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromCommunity: []string{"CUST"}, Action: ""},
				},
			},
			"EXP2": {
				Name: "EXP2",
				Terms: []*config.PolicyTerm{
					{Name: "t1", PrefixList: []string{"cust-only"}, Action: "accept"},
				},
			},
			"IMP": {
				Name: "IMP",
				Terms: []*config.PolicyTerm{
					{Name: "t1", PrefixList: []string{"cust-only"}, Action: "accept"},
				},
			},
		},
		PrefixLists: map[string]*config.PrefixList{
			"adv":       {Name: "adv", Prefixes: []string{"192.0.2.0/24", "2001:db8:1::/48"}},
			"cust-only": {Name: "cust-only", Prefixes: []string{"203.0.113.0/24", "2001:db8:3::/48"}},
		},
		Communities: map[string]*config.CommunityDef{
			"CUST": {Name: "CUST", Members: []string{"65000:100"}},
		},
	}
}

func leakFC15157() *FullConfig {
	return &FullConfig{
		PolicyOptions: leakPO15157(),
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				// A: the exporting peer (own export EXP).
				{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"EXP"}},
				// C: no export at all — the leak victim.
				{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true},
				// C6: no export, IPv6 AF.
				{Address: "2001:db8::3", PeerAS: 65003, FamilyInet6: true},
				// B: composed fall-off export — receiving peer for the
				// composed-tail arm.
				{Address: "192.0.2.2", PeerAS: 65004, FamilyInet: true, Export: []string{"TAG", "EXP2"}},
				// D: import-only neighbour (IMP) — import must stay plain.
				{Address: "192.0.2.4", PeerAS: 65005, FamilyInet: true, Import: []string{"IMP"}},
			},
		},
	}
}

func TestBGPNoExportNeighborGetsDefaultExport15157(t *testing.T) {
	got := New().buildManagedSection(leakFC15157())

	// Origination still happens (A's EXP originates static).
	if !strings.Contains(got, " redistribute static route-map EXP-static-xpf-redist\n") {
		t.Fatalf("control: #14586 origination missing:\n%s", got)
	}
	// C (no export) now attaches the Junos default export, both AFs.
	if !strings.Contains(got, "neighbor 192.0.2.3 route-map "+bgpDefaultExportNameForTest15157+" out\n") {
		t.Errorf("no-export neighbour C must attach the default-export map:\n%s", got)
	}
	if !strings.Contains(got, "neighbor 2001:db8::3 route-map "+bgpDefaultExportNameForTest15157+" out\n") {
		t.Errorf("no-export IPv6 neighbour C6 must attach the default-export map:\n%s", got)
	}
	// The definition is the Junos default: permit BGP-sourced, deny rest.
	def := routeMapBlock15157(got, bgpDefaultExportNameForTest15157)
	if def == "" ||
		!strings.Contains(def, "route-map "+bgpDefaultExportNameForTest15157+" permit 10\n match source-protocol bgp\n") ||
		!strings.Contains(def, "route-map "+bgpDefaultExportNameForTest15157+" deny 20\n") {
		t.Errorf("default-export definition must be permit-bgp then deny:\n%s", def)
	}
	// The exporting peer still receives its routes: A keeps EXP out,
	// and EXP's term still permits the static source.
	if !strings.Contains(got, "neighbor 192.0.2.1 route-map EXP out\n") {
		t.Errorf("exporting peer A must keep route-map EXP out:\n%s", got)
	}
}

func TestBGPExportTailCarvedSingle15157(t *testing.T) {
	got := New().buildManagedSection(leakFC15157())
	exp := routeMapBlock15157(got, "EXP")
	if exp == "" {
		t.Fatalf("EXP map missing:\n%s", got)
	}
	// No-default export tail: permit only BGP-sourced, then deny.
	if !strings.Contains(exp, "permit") || !strings.Contains(exp, "match source-protocol bgp") ||
		!strings.Contains(exp, "route-map EXP deny") {
		t.Errorf("EXP tail must carve (permit bgp-source, then deny):\n%s", exp)
	}
	// The carved permit must precede the deny, and there must be no
	// plain unconditional permit tail after the terms.
	bgpIdx := strings.Index(exp, "match source-protocol bgp")
	denyIdx := strings.Index(exp, "route-map EXP deny")
	if bgpIdx < 0 || denyIdx < 0 || bgpIdx > denyIdx {
		t.Errorf("carved permit must precede trailing deny:\n%s", exp)
	}
	if strings.Contains(exp, "route-map EXP permit 20\nexit") && !strings.Contains(exp, "match source-protocol bgp") {
		t.Errorf("plain permit tail survived:\n%s", exp)
	}
}

func TestBGPExportTailCarvedComposed15157(t *testing.T) {
	got := New().buildManagedSection(leakFC15157())
	composed := composedChainName([]string{"TAG", "EXP2"})
	if !strings.Contains(got, "neighbor 192.0.2.2 route-map "+composed+" out\n") {
		t.Fatalf("neighbour B must reference the composed map:\n%s", got)
	}
	def := routeMapBlock15157(got, composed)
	if def == "" {
		t.Fatalf("composed definition missing:\n%s", got)
	}
	if !strings.Contains(def, "match source-protocol bgp") ||
		!strings.Contains(def, "route-map "+composed+" deny") {
		t.Errorf("composed fall-off tail must carve (permit bgp-source, then deny); "+
			"falloff peer must receive only BGP-sourced routes:\n%s", def)
	}
	bgpIdx := strings.Index(def, "match source-protocol bgp")
	denyIdx := strings.Index(def, "route-map "+composed+" deny")
	if bgpIdx < 0 || denyIdx < 0 || bgpIdx > denyIdx {
		t.Errorf("composed carved permit must precede trailing deny:\n%s", def)
	}
}

func TestBGPImportTailStaysPlainPermit15157(t *testing.T) {
	got := New().buildManagedSection(leakFC15157())
	// D imports IMP (single, no default): import keeps plain permit,
	// never the carve. IMP is never an export anywhere.
	imp := routeMapBlock15157(got, "IMP")
	if imp == "" {
		t.Fatalf("IMP map missing:\n%s", got)
	}
	if strings.Contains(imp, "match source-protocol bgp") {
		t.Errorf("import map must NOT carve:\n%s", imp)
	}
	if !strings.Contains(imp, "route-map IMP permit") {
		t.Errorf("import map must keep the plain #2998 permit tail:\n%s", imp)
	}
	if !strings.Contains(got, "neighbor 192.0.2.4 route-map IMP in\n") {
		t.Errorf("neighbour D must keep route-map IMP in:\n%s", got)
	}
}

// Control: no #14586 origination anywhere (no export policies at all)
// renders byte-identically — no default-export map, no carve.
func TestBGPNoOriginationNoDefaultExport15157(t *testing.T) {
	fc := &FullConfig{
		PolicyOptions: leakPO15157(),
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true},
				{Address: "192.0.2.4", PeerAS: 65005, FamilyInet: true, Import: []string{"IMP"}},
			},
		},
	}
	got := New().buildManagedSection(fc)
	if strings.Contains(got, bgpDefaultExportNameForTest15157) {
		t.Errorf("no origination must not emit the default-export map:\n%s", got)
	}
	if strings.Contains(got, "neighbor 192.0.2.3 route-map") && strings.Contains(got, " out\n") {
		// C must remain attachment-less (pre-#15157 shape).
		if strings.Contains(got, "neighbor 192.0.2.3 route-map "+bgpDefaultExportNameForTest15157+" out") {
			t.Errorf("no-export neighbour gained an attachment without origination:\n%s", got)
		}
	}
	exp := routeMapBlock15157(got, "EXP")
	if strings.Contains(exp, "match source-protocol bgp") {
		t.Errorf("EXP (unused as export) must not carve without origination:\n%s", exp)
	}
}

// Control: a policy used ONLY as an import in an originating instance
// (EXP originates via A, IMP is import-only) — IMP covered above; here
// the ORIGINATING policy has an explicit default, which must stay plain.
func TestBGPExplicitDefaultExportNotCarved15157(t *testing.T) {
	po := leakPO15157()
	po.PolicyStatements["EXP"].DefaultAction = "reject"
	fc := leakFC15157()
	fc.PolicyOptions = po
	got := New().buildManagedSection(fc)
	// Neighbour set still has A exporting EXP; origination requires a
	// permit-capable export — with default reject the static term still
	// accepts, so origination exists and C still gets the default map.
	if !strings.Contains(got, "neighbor 192.0.2.3 route-map "+bgpDefaultExportNameForTest15157+" out\n") {
		t.Errorf("C must still get the default-export map:\n%s", got)
	}
	exp := routeMapBlock15157(got, "EXP")
	if strings.Contains(exp, "match source-protocol bgp") {
		t.Errorf("explicit-default export map must not carve:\n%s", exp)
	}
	if !strings.Contains(exp, "route-map EXP deny") {
		t.Errorf("explicit reject default must remain a plain deny tail:\n%s", exp)
	}
}

// Control: when EVERY neighbour carries an export, no default-export
// definition is emitted even though origination exists.
func TestBGPAllNeighboursExportNoDefaultMap15157(t *testing.T) {
	fc := leakFC15157()
	for _, n := range fc.BGP.Neighbors {
		if len(n.Export) == 0 && len(n.Import) == 0 {
			n.Export = []string{"EXP"}
		}
	}
	// D had only an import; give it an export too.
	for _, n := range fc.BGP.Neighbors {
		if n.Address == "192.0.2.4" {
			n.Export = []string{"EXP"}
		}
	}
	got := New().buildManagedSection(fc)
	if strings.Contains(got, bgpDefaultExportNameForTest15157) {
		t.Errorf("all-export config must not emit the default-export map:\n%s", got)
	}
}

// Collision belt: an operator policy forging the generated name must
// refuse the apply when the map is referenced.
func TestBGPDefaultExportCollisionRefused15157(t *testing.T) {
	fc := leakFC15157()
	fc.PolicyOptions.PolicyStatements[bgpDefaultExportNameForTest15157] = &config.PolicyStatement{
		Name:  bgpDefaultExportNameForTest15157,
		Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}},
	}
	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
	err := m.ApplyFull(fc)
	if err == nil || !strings.Contains(err.Error(), bgpDefaultExportNameForTest15157) {
		t.Fatalf("expected collision refusal naming %s, got %v", bgpDefaultExportNameForTest15157, err)
	}
}

// VRF instance: origination + a no-export neighbour inside a routing
// instance must also attach the default export (instances share the
// same render path).
func TestBGPInstanceNoExportGetsDefaultExport15157(t *testing.T) {
	fc := &FullConfig{
		PolicyOptions: leakPO15157(),
		Instances: []InstanceConfig{{
			Name:    "CUST-A",
			VRFName: "cust-a",
			BGP: &config.BGPConfig{
				LocalAS:  65010,
				RouterID: "2.2.2.2",
				Neighbors: []*config.BGPNeighbor{
					{Address: "198.51.100.1", PeerAS: 65020, FamilyInet: true, Export: []string{"EXP"}},
					{Address: "198.51.100.3", PeerAS: 65021, FamilyInet: true},
				},
			},
		}},
	}
	got := New().buildManagedSection(fc)
	if !strings.Contains(got, "neighbor 198.51.100.3 route-map "+bgpDefaultExportNameForTest15157+" out\n") {
		t.Errorf("instance no-export neighbour must attach the default-export map:\n%s", got)
	}
	if routeMapBlock15157(got, bgpDefaultExportNameForTest15157) == "" {
		t.Errorf("default-export definition missing for instance use:\n%s", got)
	}
}
