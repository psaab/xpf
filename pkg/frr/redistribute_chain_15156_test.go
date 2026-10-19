package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15156 (B07-01): an IGP `export [ P1 P2 ]` chain (OSPF/OSPFv3/RIP/IS-IS)
// and the #14586 BGP origination across several neighbours' policies rendered
// one `redistribute <proto> route-map <policy>-<proto>-xpf-redist` line per
// policy for one source. FRR keeps ONE route-map per (router, source), so
// only the last line took effect: `export [ NO-RFC1918 STATICS ]` let the
// STATICS map win and originated 10.99/16 that NO-RFC1918 was written to
// reject. Fix: exactly one redistribute per (router, AF, source) with a
// composed route-map built from the chain's per-source terms in chain order
// (terminal actions stay terminal, unmatched falls to the next policy, the
// last falls to the protocol default deny).

func chainPO15156() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"NO-RFC1918": {
				Name: "NO-RFC1918",
				Terms: []*config.PolicyTerm{
					{Name: "bad", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}}, Action: "reject"},
					{Name: "bad2", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "172.16.0.0/12", MatchType: "orlonger"}}, Action: "reject"},
					{Name: "bad3", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.168.0.0/16", MatchType: "orlonger"}}, Action: "reject"},
					// Enrolment leg (#14698): a reject-only policy enrols no
					// source on its own; the chain's accept leg enrols static
					// and this guard rides in the composed per-source map.
					{Name: "guard-fallthrough", Action: ""},
				},
			},
			"STATICS": {
				Name: "STATICS",
				Terms: []*config.PolicyTerm{
					{Name: "statics", FromProtocols: []string{"static"}, Action: "accept"},
				},
			},
		},
	}
}

func redistLinesIn15156(t *testing.T, got, header string) []string {
	t.Helper()
	start := strings.Index(got, header)
	if start < 0 {
		t.Fatalf("no %q section:\n%s", header, got)
	}
	section := got[start:]
	if end := strings.Index(section, "exit\n"); end >= 0 {
		section = section[:end]
	}
	var out []string
	for _, ln := range strings.Split(section, "\n") {
		if strings.Contains(ln, " redistribute ") {
			out = append(out, ln)
		}
	}
	return out
}

func TestOSPFExportChainSingleRedistribute15156(t *testing.T) {
	po := chainPO15156()
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF: &config.OSPFConfig{
			RouterID: "1.1.1.1",
			Export:   []string{"NO-RFC1918", "STATICS"},
			Areas: []*config.OSPFArea{
				{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}}},
			},
		},
	}
	got := New().buildManagedSection(fc)
	lines := redistLinesIn15156(t, got, "router ospf\n")
	var staticLines []string
	for _, ln := range lines {
		if strings.Contains(ln, " redistribute static ") || strings.HasSuffix(ln, " redistribute static") {
			staticLines = append(staticLines, ln)
		}
	}
	if len(staticLines) != 1 {
		t.Fatalf("export [ NO-RFC1918 STATICS ] must render exactly ONE redistribute static line, got %d: %v\n%s", len(staticLines), staticLines, got)
	}
	// NO-RFC1918-static as a standalone token must not be the attachment;
	// the composed name contains it as a prefix, so check the exact map.
	composed := "NO-RFC1918-STATICS" + ReservedChainSuffix + "-static" + config.ReservedRedistSuffix
	if !strings.Contains(staticLines[0], "route-map "+composed) {
		t.Fatalf("redistribute must reference the composed chain map %q, got %q", composed, staticLines[0])
	}
	firstDeny := strings.Index(got, "route-map "+composed+" deny")
	firstPermit := strings.Index(got, "route-map "+composed+" permit")
	if firstDeny < 0 || firstPermit < 0 || firstDeny > firstPermit {
		t.Fatalf("composed map must deny (NO-RFC1918) before permitting (STATICS): deny@%d permit@%d\n%s", firstDeny, firstPermit, got)
	}
	// Single-policy control maps still defined (used elsewhere / standalone).
	if !strings.Contains(got, "route-map NO-RFC1918-static-xpf-redist deny") {
		t.Fatalf("single-policy per-source map must remain defined\n%s", got)
	}
}

func TestOSPFExportSinglePolicyUnchanged15156(t *testing.T) {
	po := chainPO15156()
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF: &config.OSPFConfig{
			RouterID: "1.1.1.1",
			Export:   []string{"STATICS"},
			Areas: []*config.OSPFArea{
				{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}}},
			},
		},
	}
	got := New().buildManagedSection(fc)
	if !strings.Contains(got, " redistribute static route-map STATICS-static-xpf-redist\n") {
		t.Fatalf("single-policy export must keep per-source map\n%s", got)
	}
	if strings.Contains(got, ReservedChainSuffix) {
		t.Fatalf("single-policy export must not emit a composed chain map\n%s", got)
	}
}

func TestBGPOriginationAcrossNeighborChainsSingleRedistribute15156(t *testing.T) {
	po := chainPO15156()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"NO-RFC1918"}},
				{Address: "192.0.2.3", PeerAS: 65003, FamilyInet: true, Export: []string{"STATICS"}},
			},
		},
	}
	got := New().buildManagedSection(fc)
	top, _ := bgpRedistLines14586(t, got)
	var staticLines []string
	for _, ln := range top {
		if strings.Contains(ln, "redistribute static") {
			staticLines = append(staticLines, ln)
		}
	}
	if len(staticLines) != 1 {
		t.Fatalf("BGP origination across neighbours must render exactly ONE redistribute static, got %v\n%s", staticLines, got)
	}
	// OR composition: NO-RFC1918 denies precede STATICS permit.
	composed := "NO-RFC1918-STATICS" + ReservedChainSuffix + "-static" + config.ReservedRedistSuffix
	firstDeny := strings.Index(got, "route-map "+composed+" deny")
	firstPermit := strings.Index(got, "route-map "+composed+" permit")
	if firstDeny < 0 || firstPermit < 0 || firstDeny > firstPermit {
		t.Fatalf("BGP composed map must deny before permit (OR of chain accepts):\n%s", got)
	}
	if !strings.Contains(staticLines[0], composed) {
		t.Fatalf("BGP redistribute must reference composed map %q, got %q", composed, staticLines[0])
	}
}

func composedISIS15156() string {
	return "NO-RFC1918-STATICS" + ReservedChainSuffix + "-static" + config.ReservedRedistSuffix
}

func TestISISExportChainSingleRedistribute15156(t *testing.T) {
	po := chainPO15156()
	fc := &FullConfig{
		PolicyOptions: po,
		ISIS: &config.ISISConfig{
			NET:    "49.0001.0100.0100.1001.00",
			Level:  "level-2",
			Export: []string{"NO-RFC1918", "STATICS"},
		},
	}
	got := New().buildManagedSection(fc)
	lines := redistLinesIn15156(t, got, "router isis")
	count := 0
	for _, ln := range lines {
		if strings.Contains(ln, " static ") {
			count++
			if !strings.Contains(ln, composedISIS15156()) {
				t.Fatalf("IS-IS chain line must reference composed map: %q", ln)
			}
		}
	}
	// Dual-family source static → ipv4 + ipv6 lines, each one per level.
	if count < 1 {
		t.Fatalf("IS-IS chain must emit composed redistribute lines, got %v\n%s", lines, got)
	}
	// No per-policy duplicate for same (AF, source, level).
	seen := map[string]int{}
	for _, ln := range lines {
		seen[strings.TrimSpace(ln)]++
		if seen[strings.TrimSpace(ln)] > 1 {
			t.Fatalf("duplicate IS-IS redistribute line %q", ln)
		}
	}
}
