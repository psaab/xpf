package configstore

import (
	"strings"
	"testing"
)

// #16849: CheckText (the day-0 / commit-check gate, compileTreeStrict ->
// strict CompileConfig) must reject a value-less flexible-match-range on
// a discard/reject term. The valued control stays live.

func TestCheckTextRejectsValuelessFlexDiscard16849(t *testing.T) {
	text := "firewall {\n family inet {\n  filter f1 {\n   term drop-x {\n    from {\n     flexible-match-range {\n      range r1 {\n       bit-length 8;\n       byte-offset 9;\n      }\n     }\n    }\n    then discard;\n   }\n   term rest { then accept; }\n  }\n }\n}\n"
	if _, err := CheckText(text, -1); err == nil {
		t.Fatal("CheckText accepted a value-less flex discard term (#16849)")
	} else if !strings.Contains(err.Error(), "flexible-match-range") {
		t.Errorf("CheckText rejection must name flexible-match-range, got: %v", err)
	}
	valued := strings.Replace(text, "byte-offset 9;", "byte-offset 9; match-value 0x11;", 1)
	if _, err := CheckText(valued, -1); err != nil {
		t.Fatalf("CheckText rejected the valued control: %v", err)
	}
}
