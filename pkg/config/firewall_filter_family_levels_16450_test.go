package config

import (
	"strings"
	"testing"
)

// #16450: unknown children at the firewall root, family-member and
// filter levels strict-reject and lenient-warn. Each typo row pairs a
// misspelt line carrying a source-address constraint with correctly
// spelt sibling lines that build the same term without it — on the
// pre-fix tree the strict compile succeeded and the compiled term had
// an empty SourceAddresses (accept from any source).

func assertReject16450(t *testing.T, tree *ConfigTree, wantTok string) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("strict compile accepted unknown child %q (#16450)", wantTok)
	}
	if !strings.Contains(err.Error(), "#16450") || !strings.Contains(err.Error(), wantTok) {
		t.Fatalf("strict error = %q, want #16450 naming %q", err, wantTok)
	}
}

func assertLenientWarns16450(t *testing.T, tree *ConfigTree, wantTok string) *Config {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must boot (#1960): %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "#16450") || !strings.Contains(warnings, wantTok) {
		t.Fatalf("lenient warnings = %q, want #16450 naming %q", warnings, wantTok)
	}
	return cfg
}

func flat16450(lines ...string) func(*testing.T) *ConfigTree {
	return func(t *testing.T) *ConfigTree { return flatTreeFromSets(t, lines...) }
}

func hier16450(src string) func(*testing.T) *ConfigTree {
	return func(t *testing.T) *ConfigTree { return hierTree(t, src) }
}

func TestFirewallFilterFamilyLevelUnknownChildren16450(t *testing.T) {
	rows := []struct {
		name  string
		build func(*testing.T) *ConfigTree
		tok   string
	}{
		// Filter level: misspelt `term` keyword (acceptance spellings).
		{"flat trem", flat16450(
			"set firewall family inet filter wan-in trem allow-ssh from source-address 198.51.100.0/24",
			"set firewall family inet filter wan-in term allow-ssh from protocol tcp",
			"set firewall family inet filter wan-in term allow-ssh from destination-port 22",
			"set firewall family inet filter wan-in term allow-ssh then accept"), "trem"},
		{"flat terms", flat16450(
			"set firewall family inet filter wan-in terms allow-ssh from source-address 198.51.100.0/24",
			"set firewall family inet filter wan-in term allow-ssh then accept"), "terms"},
		{"flat tem", flat16450(
			"set firewall family inet filter wan-in tem allow-ssh from source-address 198.51.100.0/24",
			"set firewall family inet filter wan-in term allow-ssh then accept"), "tem"},
		// Family level: misspelt `filter` keyword.
		{"flat fitler", flat16450(
			"set firewall family inet fitler wan-in term allow-ssh from source-address 198.51.100.0/24",
			"set firewall family inet filter wan-in term allow-ssh then accept"), "fitler"},
		{"flat filters", flat16450(
			"set firewall family inet filters wan-in term allow-ssh then accept",
			"set firewall family inet filter wan-in term allow-ssh then accept"), "filters"},
		{"flat filtre inet6", flat16450(
			"set firewall family inet6 filtre wan-in term allow-ssh then accept",
			"set firewall family inet6 filter wan-in term allow-ssh then accept"), "filtre"},
		// Firewall root: abbreviated `family` (R3-B24-04 folded leg).
		{"flat fam", flat16450(
			"set firewall fam inet filter wan-in term allow-ssh then accept"), "fam"},
		{"flat root bogus", flat16450(
			"set firewall xpfbogus 5",
			"set firewall family inet filter wan-in term allow-ssh then accept"), "xpfbogus"},
		{"flat filter-level bogus", flat16450(
			"set firewall family inet filter wan-in xpfbogus 5",
			"set firewall family inet filter wan-in term allow-ssh then accept"), "xpfbogus"},
		// Hierarchical shapes.
		{"hier trem", hier16450(`firewall { family inet { filter wan-in { trem allow-ssh { from { source-address 198.51.100.0/24; } } term allow-ssh { from { protocol tcp; } then accept; } } } }`), "trem"},
		{"hier fitler", hier16450(`firewall { family inet { fitler wan-in { term allow-ssh { then accept; } } filter wan-in { term allow-ssh { then accept; } } } }`), "fitler"},
		{"hier fam", hier16450(`firewall { fam inet { filter wan-in { term allow-ssh { then accept; } } } }`), "fam"},
		{"hier set-shape trem", hier16450(`firewall { family { inet { filter wan-in { trem allow-ssh { from { source-address 198.51.100.0/24; } } term allow-ssh { then accept; } } } } }`), "trem"},
		{"hier implicit-inet trem", hier16450(`firewall { filter wan-in { trem allow-ssh { from { source-address 198.51.100.0/24; } } term allow-ssh { then accept; } } }`), "trem"},
		{"hier inet6 filtre", hier16450(`firewall { family inet6 { filtre wan-in { term allow-ssh { then accept; } } filter wan-in { term allow-ssh { then accept; } } } }`), "filtre"},
		{"hier any trem", hier16450(`firewall { family any { filter wan-in { trem allow-ssh { from { source-address 198.51.100.0/24; } } term allow-ssh { then accept; } } } }`), "trem"},
		{"hier root bogus", hier16450(`firewall { xpfbogus 5; family inet { filter wan-in { term allow-ssh { then accept; } } } }`), "xpfbogus"},
	}
	for _, tc := range rows {
		t.Run(tc.name+"/strict", func(t *testing.T) { assertReject16450(t, tc.build(t), tc.tok) })
		t.Run(tc.name+"/lenient", func(t *testing.T) { assertLenientWarns16450(t, tc.build(t), tc.tok) })
	}
}

// The acceptance headline: the widened term must not strict-commit, and
// the correctly spelt control compiles with its source constraint intact.
func TestFirewallFilterLevelControlCompiles16450(t *testing.T) {
	cfg, err := CompileConfig(flatTreeFromSets(t,
		"set firewall family inet filter wan-in term allow-ssh from source-address 198.51.100.0/24",
		"set firewall family inet filter wan-in term allow-ssh from protocol tcp",
		"set firewall family inet filter wan-in term allow-ssh from destination-port 22",
		"set firewall family inet filter wan-in term allow-ssh then accept",
		"set firewall family inet filter wan-in term drop-all then discard",
	))
	if err != nil {
		t.Fatalf("control strict compile: %v", err)
	}
	f := cfg.Firewall.FiltersInet["wan-in"]
	if f == nil || len(f.Terms) != 2 {
		t.Fatalf("control filter = %+v, want 2 terms", f)
	}
	term := f.Terms[0]
	if len(term.SourceAddresses) != 1 || term.SourceAddresses[0] != "198.51.100.0/24" {
		t.Fatalf("control term source = %v, want [198.51.100.0/24]", term.SourceAddresses)
	}
	if term.Action != FilterActionAccept {
		t.Fatalf("control term action = %q, want accept", term.Action)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16450") {
			t.Fatalf("control produced #16450 warning: %q", w)
		}
	}
}

// Lenient compilation keeps the pre-fix compiled shape (the dropped
// line stays dropped) — only the warning is new (#1960).
func TestFirewallFilterLevelLenientKeepsShape16450(t *testing.T) {
	cfg := assertLenientWarns16450(t, flatTreeFromSets(t,
		"set firewall family inet filter wan-in trem allow-ssh from source-address 198.51.100.0/24",
		"set firewall family inet filter wan-in term allow-ssh from protocol tcp",
		"set firewall family inet filter wan-in term allow-ssh then accept",
	), "trem")
	f := cfg.Firewall.FiltersInet["wan-in"]
	if f == nil || len(f.Terms) != 1 {
		t.Fatalf("lenient filter = %+v, want 1 term", f)
	}
	if len(f.Terms[0].SourceAddresses) != 0 {
		t.Fatalf("lenient term source = %v, want empty (dropped line stays dropped, warning only)", f.Terms[0].SourceAddresses)
	}
}

// Declared statements at the judged levels must not be flagged:
// interface-specific, policer/three-color-policer bodies, apply
// statements at any level, and a group-inherited typo must be judged
// exactly like an inline one (the gate runs post-expansion).
func TestFirewallLevelDeclaredAndMetaStayClean16450(t *testing.T) {
	clean := []struct {
		name  string
		build func(*testing.T) *ConfigTree
	}{
		{"interface-specific", flat16450(
			"set firewall family inet filter f interface-specific",
			"set firewall family inet filter f term t then accept")},
		{"policer", flat16450(
			"set firewall policer p1 if-exceeding bandwidth-limit 10m burst-size-limit 15k",
			"set firewall policer p1 then discard")},
		{"apply-macro in filter", hier16450(`firewall { family inet { filter f { apply-macro M { k v; } term t { then accept; } } } }`)},
		{"apply-macro at root", hier16450(`firewall { apply-macro M { k v; } family inet { filter f { term t { then accept; } } } }`)},
		{"hier control", hier16450(`firewall { family inet { filter f { term t { from { protocol tcp; } then accept; } } } }`)},
	}
	for _, tc := range clean {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.build(t))
			if err != nil {
				t.Fatalf("declared shape rejected: %v", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#16450") {
					t.Fatalf("declared shape produced #16450 warning: %q", w)
				}
			}
		})
	}
	// Group-inherited typo: judged post-expansion, same as inline.
	assertReject16450(t, flatTreeFromSets(t,
		"set groups G firewall family inet filter f trem t from source-address 10.0.0.0/24",
		"set apply-groups G",
		"set firewall family inet filter f term t then accept",
	), "trem")
}
