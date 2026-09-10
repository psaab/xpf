package config

import (
	"strings"
	"testing"
)

// #9570: ZonePairGlobalSentinelSide is the single predicate the strict commit
// text and the userspace snapshot builder's poison share. The accepting rows
// are the ones a careless predicate breaks: the other reserved tokens, a zone
// whose name merely contains the sentinel, and a different case (zone names are
// case-sensitive, and the helper compares bytes).
func TestZonePairGlobalSentinelSide9570(t *testing.T) {
	for _, tc := range []struct{ from, to, want string }{
		{"junos-global", "trust", "from-zone"},
		{"trust", "junos-global", "to-zone"},
		{"junos-global", "junos-global", "from-zone and to-zone"},
		{"any", "junos-global", "to-zone"},
		{"junos-global", "any", "from-zone"},

		{"trust", "untrust", ""},
		{"any", "any", ""},
		{"trust", "junos-host", ""},
		{"junos-global-edge", "trust", ""},
		{"trust", "my-junos-global", ""},
		{"Junos-Global", "trust", ""},
		{"", "", ""},
	} {
		if got := ZonePairGlobalSentinelSide(tc.from, tc.to); got != tc.want {
			t.Errorf("ZonePairGlobalSentinelSide(%q, %q) = %q, want %q", tc.from, tc.to, got, tc.want)
		}
	}
}

func zonePairPolicyLines9570(from, to, name, action string) []string {
	p := "set security policies from-zone " + from + " to-zone " + to + " policy " + name + " "
	return []string{
		p + "match source-address any",
		p + "match destination-address any",
		p + "match application any",
		p + "then " + action,
	}
}

// TestZonePairJunosGlobalCommitErrorNamesTheReservedContext9570 pins the
// operator-facing text on BOTH compile channels.
//
// Strict (CompileConfig, the gate `commit` and configstore.CheckText run): the
// generic undefined-zone error told the operator to define `security-zone
// junos-global`, which #3055 rejects, and said the rule would be "silently never
// matched", which was false for this token — the helper enforced it as a
// device-wide global rule. Tolerant (CompileConfigLenient, boot load / HA sync /
// upgrade): the same text is the load warning, so it must be accurate there too.
//
// The typo-zone row is the control that the dedicated arm did not swallow the
// ordinary undefined-zone error.
func TestZonePairJunosGlobalCommitErrorNamesTheReservedContext9570(t *testing.T) {
	for _, tc := range []struct{ name, from, to, side string }{
		{"from-side", "junos-global", "trust", "from-zone"},
		{"to-side", "trust", "junos-global", "to-zone"},
		{"both-sided", "junos-global", "junos-global", "from-zone and to-zone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := append([]string{"set security zones security-zone trust"},
				zonePairPolicyLines9570(tc.from, tc.to, "p1", "permit")...)
			_, err := CompileConfig(buildTree(t, lines))
			if err == nil {
				t.Fatal("strict commit accepted a zone-pair stanza naming junos-global")
			}
			msg := err.Error()
			for _, want := range []string{`"junos-global"`, "as its " + tc.side + ":", "reserved global-policy context", "security policies global"} {
				if !strings.Contains(msg, want) {
					t.Errorf("strict error does not contain %q: %s", want, msg)
				}
			}
			for _, bad := range []string{"silently never matched", "define `set security zones security-zone junos-global`"} {
				if strings.Contains(msg, bad) {
					t.Errorf("strict error still carries the false undefined-zone advice %q: %s", bad, msg)
				}
			}

			cfg, lerr := CompileConfigLenient(buildTree(t, lines))
			if lerr != nil {
				t.Fatalf("tolerant compile must keep the stanza with a warning (#1960 no-brick), got %v", lerr)
			}
			warned := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "reserved global-policy context") && strings.Contains(w, "as its "+tc.side+":") {
					warned = true
				}
			}
			if !warned {
				t.Errorf("tolerant compile did not warn with the reserved-context text; warnings: %v", cfg.Warnings)
			}
		})
	}

	t.Run("typo-zone control keeps the undefined-zone error", func(t *testing.T) {
		lines := append([]string{"set security zones security-zone trust"},
			zonePairPolicyLines9570("typo-zone", "trust", "p1", "permit")...)
		_, err := CompileConfig(buildTree(t, lines))
		if err == nil || !strings.Contains(err.Error(), `references undefined from-zone "typo-zone"`) {
			t.Fatalf("an ordinary undefined zone must keep its own error, got %v", err)
		}
		if strings.Contains(err.Error(), "reserved global-policy context") {
			t.Fatalf("the reserved-context arm fired for an ordinary typo: %v", err)
		}
	})
}
