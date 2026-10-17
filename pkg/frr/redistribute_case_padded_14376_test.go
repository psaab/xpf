package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14376: a bare redistribute token arriving case-variant or padded
// (export BGP under router bgp, export OSPF6 under router ospf,
// export " bgp" under router bgp) on the lenient load / peer-sync path
// passes knownRedistProtocol (which trims + lower-cases via
// FRRRoutingProtocolKeyword) but redistributeEntriesAt emitted the RAW
// token: the self check (export == self) and the AFI check
// (redistSourceFitsNode, keyed by canonical keywords) compared the raw
// string, missed, and formatRedistEntries rendered
// `redistribute BGP` / `redistribute OSPF6` / `redistribute  bgp`,
// which FRR rejects, failing the whole managed reload.
//
// The renderer must canonicalize the token once, so every gate and every
// emitted line sees the canonical keyword. These cells pin ZERO
// redistribute lines for the decisive fixtures (with the existing skip
// warnings, which the bare-branch slog paths already emit) and pin that
// redistributeEntriesAt never emits a non-canonical protocol token.
// Controls pin that canonicalizing does not change valid rendering:
// a valid non-self token still renders (canonicalized), and a quoted
// padded valid token renders its canonical form.

func buildTree14376(t *testing.T, cmds []string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, c := range cmds {
		p, err := config.ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	return tree
}

func renderLenient14376(t *testing.T, cmds []string) (string, *config.Config) {
	t.Helper()
	cfg, err := config.CompileConfigLenient(buildTree14376(t, cmds))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	m := New()
	out := m.generateProtocols(cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.BGP,
		cfg.Protocols.RIP, cfg.Protocols.ISIS, "", 0, &cfg.PolicyOptions, nil)
	return out, cfg
}

// TestRedistributeCasePaddedBareTokenSkipped14376 is the decisive
// regression from the issue: the three named spellings render ZERO
// redistribute lines.
func TestRedistributeCasePaddedBareTokenSkipped14376(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{"export BGP under router bgp (self, case-variant)",
			[]string{"set protocols bgp local-as 65001", `set protocols bgp export BGP`}},
		{"export OSPF6 under router ospf (AFI mismatch, case-variant)",
			[]string{"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0", `set protocols ospf export OSPF6`}},
		{"export padded bgp under router bgp (self, padded)",
			[]string{"set protocols bgp local-as 65001", `set protocols bgp export " bgp"`}},
		// Same mechanism, neighbouring spellings: padded self under ospf,
		// padded AFI mismatch under ospf.
		{"export padded ospf under router ospf (self, padded)",
			[]string{"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0", `set protocols ospf export " ospf"`}},
		{"export padded OSPF6 under router ospf (AFI mismatch, padded+case)",
			[]string{"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0", `set protocols ospf export " OSPF6"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, cfg := renderLenient14376(t, tc.cmds)
			// Precondition: lenient path kept the raw token (strict would
			// reject some of these; the lenient compile must not fail).
			_ = cfg
			for _, l := range strings.Split(out, "\n") {
				if strings.Contains(l, "redistribute") {
					t.Errorf("must render ZERO redistribute lines, got line %q in:\n%s", l, out)
				}
			}
		})
	}
}

// TestRedistributeEntriesAtNeverEmitsNonCanonical14376 pins the renderer
// invariant directly: for a battery of case/padded spellings, every
// entry redistributeEntriesAt returns carries the canonical keyword
// (or no entry at all), and self/AFI filtering uses the canonical form.
func TestRedistributeEntriesAtNeverEmitsNonCanonical14376(t *testing.T) {
	m := New()
	for _, tc := range []struct {
		export, self, node string
		want               []redistEntry // nil = skipped
	}{
		// Decisive: self and AFI gates must see the canonical token.
		{"BGP", "bgp", "bgp", nil},
		{"OSPF6", "ospf", "ospf", nil},
		{" bgp", "bgp", "bgp", nil},
		{" ospf", "ospf", "ospf", nil},
		{" OSPF6", "ospf", "ospf", nil},
		{"OSPF6 ", "ospf", "ospf", nil},
		// BGP IPv6 node: canonical ospf6 fits, canonical bgp is self.
		{"OSPF6", "bgp", "bgp-ipv6", []redistEntry{{proto: "ospf6"}}},
		{" BGP", "bgp", "bgp-ipv6", nil},
		// Valid non-self tokens render canonicalized, never raw.
		{"STATIC", "ospf", "ospf", []redistEntry{{proto: "static"}}},
		{" static ", "ospf", "ospf", []redistEntry{{proto: "static"}}},
		{"DIRECT", "ospf", "ospf", []redistEntry{{proto: "connected"}}},
		{"Ospf", "bgp", "bgp", []redistEntry{{proto: "ospf"}}},
		// Canonical controls unchanged.
		{"static", "ospf", "ospf", []redistEntry{{proto: "static"}}},
		{"ospf", "ospf", "ospf", nil},
		{"ospf6", "ospf", "ospf", nil},
	} {
		got := m.redistributeEntriesAt(tc.export, nil, tc.self, tc.node)
		if len(got) != len(tc.want) {
			t.Errorf("redistributeEntriesAt(%q, self=%q, node=%q) = %v, want %v", tc.export, tc.self, tc.node, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("redistributeEntriesAt(%q, self=%q, node=%q)[%d] = %+v, want %+v", tc.export, tc.self, tc.node, i, got[i], tc.want[i])
			}
			kw, ok := config.FRRRoutingProtocolKeyword(got[i].proto)
			if !ok || kw != got[i].proto {
				t.Errorf("redistributeEntriesAt(%q) emitted non-canonical proto %q", tc.export, got[i].proto)
			}
		}
	}
	// ISIS formatting shares the same entries; a case-variant self must
	// also be dropped there (entries are empty, so no line at all).
	if got := m.resolveISISRedistribute("ISIS", nil, "", nil); got != "" {
		t.Errorf("ISIS self (case-variant) must render nothing, got %q", got)
	}
	if got := m.resolveISISRedistribute("STATIC", nil, "", nil); !strings.Contains(got, "redistribute ipv4 static") {
		t.Errorf("ISIS STATIC must render canonical static, got %q", got)
	}
}

// TestRedistributeCasePaddedControls14376 pins that canonicalization
// does not break valid rendering through the full lenient compile +
// generateProtocols path: valid / braced / single / no-policy controls.
func TestRedistributeCasePaddedControls14376(t *testing.T) {
	// Valid canonical token still renders.
	out, _ := renderLenient14376(t, []string{
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
		"set protocols ospf export static",
	})
	if !strings.Contains(out, " redistribute static\n") {
		t.Errorf("valid export static must render, got:\n%s", out)
	}
	// Valid case-variant non-self token renders its canonical form,
	// never the raw spelling, in both BGP nodes.
	out, _ = renderLenient14376(t, []string{
		"set protocols bgp local-as 65001",
		`set protocols bgp export " OSPF6"`,
	})
	if strings.Contains(out, "OSPF6") {
		t.Errorf("raw case/padded token must never render, got:\n%s", out)
	}
	if !strings.Contains(out, "redistribute ospf6") {
		t.Errorf("canonical ospf6 must render in the IPv6 address family, got:\n%s", out)
	}
	// QNH/metric path keyed on `static`: a lowercase static still gets
	// its route-map through redistributeEntries (unchanged behaviour is
	// pinned by the metric suites; here the canonical entry proto must
	// stay "static" so applyQNHMetricRouteMap11447 matches it).
	entries := New().redistributeEntriesAt("static", nil, "ospf", "ospf")
	if len(entries) != 1 || entries[0].proto != "static" {
		t.Fatalf("static entries = %v, want one canonical static entry", entries)
	}
	// Defined policy-statement path is untouched: a policy whose terms
	// carry canonical protocols still expands per protocol.
	po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		"exp": {Name: "exp", Terms: []*config.PolicyTerm{
			{Name: "t", FromProtocols: []string{"static"}, Action: "accept"},
		}},
	}}
	if got := New().resolveRedistribute("exp", po, "ospf", nil); got != " redistribute static route-map exp-static-xpf-redist\n" {
		t.Errorf("policy path changed: got %q", got)
	}
}
