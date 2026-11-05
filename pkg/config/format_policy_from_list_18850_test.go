package config

import (
	"strings"
	"testing"
)

// A quoted keyword does not make its neighboring bare keyword safe to render
// outside the brackets: the unquoted member still needs bracket provenance to
// remain a value on Format->Parse replay.
func TestFormatQuotedListKeepsBareInlineKeyword18850(t *testing.T) {
	tree := parseHierText(t, `policy-options {
 prefix-list protocol 10.0.0.0/8;
 prefix-list then 172.16.0.0/12;
 policy-statement P {
  term T {
   from prefix-list [ protocol "then" ];
   then reject;
  }
 }
}`)
	formatted := tree.Format()
	if !strings.Contains(formatted, `from prefix-list [ protocol "then" ]`) {
		t.Fatalf("Format removed brackets needed by the bare keyword member:\n%s", formatted)
	}
	replayed := parseHierText(t, formatted)
	cfg, err := CompileConfig(replayed)
	if err != nil {
		t.Fatalf("replay compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.PrefixList) != 2 || term.PrefixList[0] != "protocol" ||
		term.PrefixList[1] != "then" || len(term.UnknownFrom) != 0 ||
		term.Action != "reject" {
		t.Fatalf("Format replay changed bracketed values: PrefixList=%v UnknownFrom=%v Action=%q",
			term.PrefixList, term.UnknownFrom, term.Action)
	}
}
