package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// lo0_from_unrepresentable_9875_test.go is the daemon half of the #9875 proof.
// The nftables half (pkg/nftables/netlink_lo0_from_unrepresentable_9875_test.go)
// proves the production BUILDER fails closed; this half proves three things it
// cannot see:
//
//  1. reachability — the marker actually reaches that builder on the production
//     path (toNftLo0Spec -> InstallLo0), for BOTH recording channels
//     (term.UnknownFrom, #3307; term.ValuelessFrom, #8480);
//  2. the TEXT oracle (buildLo0FilterPayload) fails the same input the same way,
//     via the nft-invalid __xpf_refuse_unrepresentable_from__ bareword;
//  3. the two renderers AGREE. That is the assertion that matters: before this
//     fix they agreed too — both rendered the surviving predicates — so a
//     parity test alone could never have caught the defect. Agreement is
//     asserted on the PROPERTY (neither renderer may emit a term whose
//     constraint vanished), not on a literal one of them happens to produce.
//
// Strict commit rejects these spellings (validateFilterFromMatchStrict,
// validateFirewallFilterValuelessFromStrict), so every fixture here is the
// tolerant shape: a leniently loaded / peer-synced / mixed-version config,
// which is precisely the live ingress #1960 keeps open.

func d9875() *Daemon { return &Daemon{} }

// lo0Cfg9875 builds a one-term inet lo0 filter config around the supplied term.
func lo0Cfg9875(term *config.FirewallFilterTerm) *config.Config {
	cfg := &config.Config{}
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{term}},
	}
	return cfg
}

// lowerLo0Term9875 runs the production lowering and returns the single lowered
// term the netlink installer would receive.
func lowerLo0Term9875(t *testing.T, cfg *config.Config) xnft.Lo0FilterTerm {
	t.Helper()
	var got xnft.Lo0FilterSpec
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0: func(s xnft.Lo0FilterSpec) error { got = s; return nil },
	}
	defer func() { nftInstaller = orig }()

	if err := d9875().applyLo0Filter(cfg); err != nil {
		t.Fatalf("applyLo0Filter: %v", err)
	}
	if len(got.V4Terms) != 1 {
		t.Fatalf("want 1 lowered v4 term, got %d", len(got.V4Terms))
	}
	return got.V4Terms[0]
}

// TestUnknownFromReachesLo0Builder9875 pins the reachability half for a whole
// `from` leaf the dataplane does not enforce (#3307). The surviving
// predicates carry no trace of it, so without the marker the builder is
// structurally unable to fail closed.
func TestUnknownFromReachesLo0Builder9875(t *testing.T) {
	term := lowerLo0Term9875(t, lo0Cfg9875(&config.FirewallFilterTerm{
		Name: "ttl-term", Protocols: []string{"tcp"},
		UnknownFrom: []string{"ttl"}, Action: "accept",
	}))
	if !term.FromUnrepresentable {
		t.Error("#9875: UnknownFrom must set FromUnrepresentable — without it " +
			"the builder sees a tcp-only term and admits every TTL")
	}
}

// TestValuelessFromReachesLo0Builder9875 pins the reachability half for a
// value-bearing leaf written with NO operand (#8480). Post-compile the
// valueless and omitted forms are byte-identical, so the marker is again the
// only channel.
func TestValuelessFromReachesLo0Builder9875(t *testing.T) {
	term := lowerLo0Term9875(t, lo0Cfg9875(&config.FirewallFilterTerm{
		Name: "empty-proto", ValuelessFrom: []string{"protocol"}, Action: "accept",
	}))
	if !term.FromUnrepresentable {
		t.Error("#9875: ValuelessFrom must set FromUnrepresentable — without it " +
			"the builder sees an unconstrained term and matches everything")
	}
}

// TestRepresentableFromDoesNotSetUnrepresentable9875 is the anti-over-fix
// control for the marker: a fully representable term must NOT be marked, or
// every ordinary lo0 filter would fail its install.
func TestRepresentableFromDoesNotSetUnrepresentable9875(t *testing.T) {
	term := lowerLo0Term9875(t, lo0Cfg9875(&config.FirewallFilterTerm{
		Name: "ok", Protocols: []string{"tcp"},
		DestinationPorts: []string{"22"}, Action: "accept",
	}))
	if term.FromUnrepresentable {
		t.Fatal("a fully representable term must not be marked unrepresentable")
	}
}

// TestLo0TextOracleRefusesUnrepresentableFrom9875 pins the text half. The
// oracle has no error channel — buildLo0FilterPayload returns a string — so
// its fail-closed idiom is the CONSTANT nft-invalid refusal rule
// (nftRefuseUnrepresentableFrom), which makes `nft -f -` REJECT the whole
// ruleset and retain the prior generation (#6806 posture). Constant by
// design (GPT-3): UnknownFrom holds raw node names and the lexer permits
// embedded quotes, so interpolating the leaf names would make rejection
// isolation depend on diagnostic contents. The adversarial case pins that
// the emitted rule is byte-identical with hostile input — and that the
// hostile name appears nowhere in the payload (it is reported via slog).
func TestLo0TextOracleRefusesUnrepresentableFrom9875(t *testing.T) {
	adversarial := `weird"; drop table inet xpf_lo0; --`
	cases := []struct {
		name string
		term *config.FirewallFilterTerm
		raw  string // hostile input that must NOT reach the payload ("" = none)
	}{
		{
			name: "unknown_from",
			term: &config.FirewallFilterTerm{
				Name: "ttl-term", Protocols: []string{"tcp"},
				UnknownFrom: []string{"ttl"}, Action: "accept",
			},
		},
		{
			name: "valueless_from",
			term: &config.FirewallFilterTerm{
				Name: "empty-proto", ValuelessFrom: []string{"protocol"}, Action: "accept",
			},
		},
		{
			name: "adversarial unknown name (GPT-3)",
			term: &config.FirewallFilterTerm{
				Name: "evil", Protocols: []string{"tcp"},
				UnknownFrom: []string{adversarial}, Action: "accept",
			},
			raw: adversarial,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := buildLo0FilterPayload(lo0Cfg9875(tc.term), "protect-re", "")
			if !strings.Contains(payload, nftRefuseUnrepresentableFrom) {
				t.Fatalf("#9875: the oracle must emit the constant refusal rule so the nft load fails "+
					"closed; payload:\n%s", payload)
			}
			if tc.raw != "" && strings.Contains(payload, tc.raw) {
				t.Fatalf("#9875: hostile leaf name %q reached the nft payload — rejection isolation "+
					"depends on diagnostic contents; payload:\n%s", tc.raw, payload)
			}
		})
	}
}

// TestLo0TextOracleUnchangedForRepresentableFrom9875 is the no-regression
// half of the oracle change: a term with no unrepresentable leaf must render
// exactly as before. A fix that changed this would move every existing
// parity golden.
func TestLo0TextOracleUnchangedForRepresentableFrom9875(t *testing.T) {
	payload := buildLo0FilterPayload(lo0Cfg9875(&config.FirewallFilterTerm{
		Name: "ok", Protocols: []string{"tcp"},
		DestinationPorts: []string{"22"}, Action: "accept",
	}), "protect-re", "")
	if strings.Contains(payload, "__xpf_refuse_unrepresentable_from__") {
		t.Errorf("a representable term must not carry the refusal bareword; payload:\n%s", payload)
	}
	if !strings.Contains(payload, "meta l4proto 6") {
		t.Errorf("a resolvable protocol must still render numerically; payload:\n%s", payload)
	}
	if !strings.Contains(payload, "th dport 22") {
		t.Errorf("a resolvable port must still render; payload:\n%s", payload)
	}
}

// TestLo0RenderersAgreeOnUnrepresentableFrom9875 is the assertion that makes
// the pair trustworthy, mirroring TestLo0RenderersAgreeOnUnresolvableTokens6806:
// what must hold is that NEITHER mirror loses the refusal evidence at its own
// boundary, for the same input:
//
//   - text: the refusal bareword survives into the payload, so `nft -f -`
//     refuses the whole ruleset and the prior generation is retained;
//   - netlink: the lowered DTO carries the marker the builder refuses on.
//     That the builder then DOES refuse is proven in the nftables half
//     (TestLo0FromUnrepresentableFailsClosed9875); this cell is the seam
//     between the two halves.
//
// Break either side and this cell reds while the other side stays green, which
// is what makes it a localising assertion rather than a second copy of the
// halves it joins.
func TestLo0RenderersAgreeOnUnrepresentableFrom9875(t *testing.T) {
	cases := []struct {
		name string
		term *config.FirewallFilterTerm
	}{
		{
			name: "unknown_from",
			term: &config.FirewallFilterTerm{
				Name: "ttl-term", Protocols: []string{"tcp"},
				UnknownFrom: []string{"ttl"}, Action: "accept",
			},
		},
		{
			name: "valueless_from",
			term: &config.FirewallFilterTerm{
				Name: "empty-proto", ValuelessFrom: []string{"protocol"}, Action: "accept",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lo0Cfg9875(tc.term)
			oracle := buildLo0FilterPayload(cfg, "protect-re", "")
			if !strings.Contains(oracle, "__xpf_refuse_unrepresentable_from__") {
				t.Errorf("text side lost the refusal evidence; payload:\n%s", oracle)
			}
			lowered := lowerLo0Term9875(t, cfg)
			if !lowered.FromUnrepresentable {
				t.Error("netlink side lost the refusal evidence: FromUnrepresentable is false")
			}
		})
	}
}

// TestLo0TextOracleRefusesMarkedMatchNothing9875 pins the GPT-2 ordering on
// the text side: the marker preflight runs ahead of address elimination, so
// a marked term refuses the whole load even when it is also match-nothing
// (here: v6-only addresses rendered into the v4 chain). Letting it skip
// would install the remaining ruleset — including the healthy term below —
// while the Rust side rejects the same snapshot.
func TestLo0TextOracleRefusesMarkedMatchNothing9875(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "ok", Protocols: []string{"tcp"}, Action: "accept"},
			{Name: "marked-nothing", SourceAddresses: []string{"2001:db8::1/128"},
				UnknownFrom: []string{"ttl"}, Action: "accept"},
		}},
	}
	payload := buildLo0FilterPayload(cfg, "protect-re", "")
	if !strings.Contains(payload, nftRefuseUnrepresentableFrom) {
		t.Fatalf("#9875: a marked match-nothing term must refuse the whole load, not skip; "+
			"payload:\n%s", payload)
	}
}
