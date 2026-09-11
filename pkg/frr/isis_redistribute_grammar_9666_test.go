package frr

import (
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9666: isisd installs only
//
//	redistribute <ipv4|ipv6> <proto> <level-1|level-2> [route-map X]
//
// (FRR stable/10.6 isis_cli.c isis_redistribute_cmd). Every IS-IS export used
// to render the OSPF-shaped `redistribute <proto>`, which isisd rejects, and one
// rejected line fails the whole managed reload.

var isisRedistLine9666 = regexp.MustCompile(`^ redistribute (ipv4|ipv6) \S+ level-[12]( route-map \S+)?$`)

func isisBlock9666(t *testing.T, isis *config.ISISConfig, po *config.PolicyOptionsConfig) []string {
	t.Helper()
	got := New().generateProtocols(nil, nil, nil, nil, isis, "", 0, po, nil)
	start := strings.Index(got, "router isis xpf\n")
	if start < 0 {
		t.Fatalf("no IS-IS block rendered:\n%s", got)
	}
	block := got[start:]
	if end := strings.Index(block, "\nexit\n"); end >= 0 {
		block = block[:end]
	}
	var lines []string
	for _, ln := range strings.Split(block, "\n") {
		if strings.HasPrefix(ln, " redistribute") {
			lines = append(lines, ln)
		}
	}
	return lines
}

func TestISISRedistributeUsesTheIsisdGrammar9666(t *testing.T) {
	for _, c := range []struct {
		name, level string
		export      []string
		want        []string
	}{
		{"level-2 dual-family source", "level-2", []string{"static"},
			[]string{" redistribute ipv4 static level-2", " redistribute ipv6 static level-2"}},
		{"level-1", "level-1", []string{"connected"},
			[]string{" redistribute ipv4 connected level-1", " redistribute ipv6 connected level-1"}},
		{"level-1-2 renders one line per level", "level-1-2", []string{"static"},
			[]string{" redistribute ipv4 static level-1", " redistribute ipv4 static level-2",
				" redistribute ipv6 static level-1", " redistribute ipv6 static level-2"}},
		{"unset is-type takes the narrow default", "", []string{"static"},
			[]string{" redistribute ipv4 static level-2", " redistribute ipv6 static level-2"}},
		{"unrecognized is-type takes the narrow default", "garbage", []string{"static"},
			[]string{" redistribute ipv4 static level-2", " redistribute ipv6 static level-2"}},
		{"IPv4-only source", "level-2", []string{"ospf"}, []string{" redistribute ipv4 ospf level-2"}},
		{"IPv6-only source", "level-2", []string{"ospf6"}, []string{" redistribute ipv6 ospf6 level-2"}},
		{"ripng is IPv6-only", "level-2", []string{"ripng"}, []string{" redistribute ipv6 ripng level-2"}},
		{"direct normalises to connected", "level-2", []string{"direct"},
			[]string{" redistribute ipv4 connected level-2", " redistribute ipv6 connected level-2"}},
		{"self-redistribution is still dropped", "level-2", []string{"isis"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := isisBlock9666(t, &config.ISISConfig{NET: "49.0001.1921.6800.1001.00", Level: c.level, Export: c.export}, nil)
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Fatalf("redistribute lines =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
		})
	}
}

// A policy-statement export renders one route-map line per source, family and
// level, in the isisd form.
func TestISISRedistributePolicyUsesTheIsisdGrammar9666(t *testing.T) {
	po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		"to-isis": {Name: "to-isis", Terms: []*config.PolicyTerm{
			{Name: "t1", FromProtocols: []string{"static", "ospf"}, Action: "accept"},
		}},
	}}
	got := isisBlock9666(t, &config.ISISConfig{NET: "49.0001.1921.6800.1001.00", Level: "level-2", Export: []string{"to-isis"}}, po)
	want := []string{
		" redistribute ipv4 ospf level-2 route-map to-isis",
		" redistribute ipv4 static level-2 route-map to-isis",
		" redistribute ipv6 static level-2 route-map to-isis",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("redistribute lines =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// The acceptance's second bullet: no line under `router isis` is the plain
// OSPF-shaped form, over every source and every is-type.
func TestISISNeverRendersThePlainRedistributeForm9666(t *testing.T) {
	for _, level := range []string{"level-1", "level-2", "level-1-2", "", "garbage"} {
		lines := isisBlock9666(t, &config.ISISConfig{
			NET: "49.0001.1921.6800.1001.00", Level: level,
			Export: []string{"static", "connected", "direct", "kernel", "bgp", "ospf", "ospf6", "rip", "ripng"},
		}, nil)
		if len(lines) == 0 {
			t.Fatalf("level %q: no redistribute lines at all", level)
		}
		for _, ln := range lines {
			if !isisRedistLine9666.MatchString(ln) {
				t.Errorf("level %q: %q is not isisd grammar", level, ln)
			}
		}
	}
}

// OSPF keeps its own grammar: the refactor into redistributeEntries leaves the
// OSPF-shaped line byte-identical.
func TestOSPFRedistributeLineIsUnchanged9666(t *testing.T) {
	got := New().resolveRedistribute("static", nil, "ospf", nil)
	if got != " redistribute static\n" {
		t.Fatalf("ospf redistribute = %q, want %q", got, " redistribute static\n")
	}
}
