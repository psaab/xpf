package config

import (
	"strings"
	"testing"
)

// trapOptionsWarnings9562 compiles one spelling on the strict AND the tolerant
// path and returns each path's `snmp trap-options` advisories. Every row is an
// operator-valid config that committed clean before #9562, so a refusal on any
// channel fails the cell: the remedy is an advisory, never a reject (#1960).
func trapOptionsWarnings9562(t *testing.T, sp spelling9414) (strict, lenient []string) {
	t.Helper()
	pick := func(ws []string) []string {
		var out []string
		for _, w := range ws {
			if strings.HasPrefix(w, "snmp trap-options ") {
				out = append(out, w)
			}
		}
		return out
	}
	sc, err := CompileConfig(sp.tree(t))
	if err != nil {
		t.Fatalf("%s: strict CompileConfig REJECTED an operator-valid config: %v", sp.label, err)
	}
	if err := SchemaValidate(sp.tree(t), sc); err != nil {
		t.Fatalf("%s: SchemaValidate REJECTED an operator-valid config: %v", sp.label, err)
	}
	lc, err := CompileConfigLenient(sp.tree(t))
	if err != nil {
		t.Fatalf("%s: CompileConfigLenient REJECTED an operator-valid config: %v", sp.label, err)
	}
	return pick(sc.Warnings), pick(lc.Warnings)
}

// #9562: compileSNMP has no trap-options arm, so every child compiles to
// nothing, yet only `source-address` was advised. Each statement must now be
// loud in every spelling on both paths. Each row names the phrase that is TRUE
// for it: the generic "no-op" text also starts with the right prefix, so a prefix
// alone could not tell a precise advisory from a lost one.
func TestSNMPTrapOptionsStatementsAreLoudInEverySpelling9562(t *testing.T) {
	for _, r := range []struct {
		kw, stanza, flat, phrase, value string
	}{
		{"source-address", "source-address 10.0.0.1", "source-address 10.0.0.1", "default egress IP", "10.0.0.1"},
		{"routing-instance", "routing-instance mgmt9562", "routing-instance mgmt9562", "default routing instance", "mgmt9562"},
		{"context-oid", "context-oid", "context-oid", "no context varbind", ""},
		{"agent-address", "agent-address outgoing-interface", "agent-address outgoing-interface", "per-target source address", ""},
		{"logical-system", "logical-system ls9562", "logical-system ls9562", "no-op", "ls9562"},
	} {
		for _, sp := range []spelling9414{
			{label: "braced", braced: "snmp { trap-options { " + r.stanza + "; } }"},
			{label: "brace-elided", braced: "snmp { trap-options " + r.stanza + "; }"},
			{label: "flat-set", flat: []string{"set snmp trap-options " + r.flat}},
		} {
			r, sp := r, sp
			t.Run(r.kw+"/"+sp.label, func(t *testing.T) {
				strict, lenient := trapOptionsWarnings9562(t, sp)
				for _, ch := range []struct {
					name string
					ws   []string
				}{{"strict", strict}, {"lenient", lenient}} {
					prefix := "snmp trap-options " + r.kw + ":"
					found := false
					for _, w := range ch.ws {
						if !strings.HasPrefix(w, prefix) {
							t.Errorf("%s: an advisory for a statement this config does not contain: %q", ch.name, w)
							continue
						}
						if !strings.Contains(w, r.phrase) {
							t.Errorf("%s: %q does not say %q, which is what is true for %s", ch.name, w, r.phrase, r.kw)
						}
						if r.value != "" && strings.Contains(w, r.value) {
							t.Errorf("%s: echoed the configured value %q: %q", ch.name, r.value, w)
						}
						found = true
					}
					if !found {
						t.Errorf("%s: `trap-options %s` compiled to nothing with no advisory; warnings %q", ch.name, r.kw, ch.ws)
					}
				}
			})
		}
	}
}

// Several statements in one stanza each get their own advisory, and a config
// with no trap-options gets none: "every snmp stanza warns" would pass the loud
// rows above, and these are the rows that refuse it.
func TestSNMPTrapOptionsAdvisoryIsPerStatement9562(t *testing.T) {
	strict, lenient := trapOptionsWarnings9562(t, spelling9414{label: "braced",
		braced: "snmp { trap-options { routing-instance mgmt9562; context-oid; agent-address outgoing-interface; } }"})
	for _, ws := range [][]string{strict, lenient} {
		if len(ws) != 3 {
			t.Errorf("want one advisory per statement (3), got %q", ws)
		}
	}
	for _, sp := range []spelling9414{
		{label: "trap-group only", braced: "snmp { trap-group tg1 { targets 10.0.0.9; } }"},
		{label: "contact only", braced: `snmp { contact "noc"; }`},
	} {
		strict, lenient := trapOptionsWarnings9562(t, sp)
		if len(strict)+len(lenient) != 0 {
			t.Errorf("%s raised a trap-options advisory: %q %q", sp.label, strict, lenient)
		}
	}
}
