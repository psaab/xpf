package configstore

import (
	"strings"
	"testing"
)

// #16244: the day-0 / commit-check gate (CheckText -> compileTreeStrict
// -> CompileConfig) must refuse MTU 9000 on a userspace-dataplane-bound
// interface with the named refusal, so an invalid jumbo config never
// reaches the daemon. An at-budget MTU and an unzoned jumbo interface
// still pass.

func TestCheckTextRejectsJumboBoundMTU16244(t *testing.T) {
	text := "interfaces {\n" +
		"    ge-0/0/1 {\n" +
		"        mtu 9000;\n" +
		"        unit 0 { family inet { address 10.0.1.1/24; } }\n" +
		"    }\n" +
		"}\n" +
		"security { zones { security-zone trust { interfaces { ge-0/0/1.0; } } } }\n"
	_, err := CheckText(text, -1)
	if err == nil {
		t.Fatal("CheckText ACCEPTED MTU 9000 on a dataplane-bound interface")
	}
	for _, want := range []string{"ge-0/0/1", "9000", "#16244"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CheckText refusal %q does not name %q", err.Error(), want)
		}
	}
}

func TestCheckTextAcceptsAtBudgetAndUnzoned16244(t *testing.T) {
	atBudget := "interfaces {\n" +
		"    ge-0/0/1 {\n" +
		"        mtu 3566;\n" +
		"        unit 0 { family inet { address 10.0.1.1/24; } }\n" +
		"    }\n" +
		"}\n" +
		"security { zones { security-zone trust { interfaces { ge-0/0/1.0; } } } }\n"
	if _, err := CheckText(atBudget, -1); err != nil {
		t.Fatalf("CheckText rejected at-budget MTU 3566: %v", err)
	}
	unzoned := "interfaces {\n" +
		"    ge-0/0/1 {\n" +
		"        mtu 9000;\n" +
		"        unit 0 { family inet { address 10.0.1.1/24; } }\n" +
		"    }\n" +
		"}\n"
	if _, err := CheckText(unzoned, -1); err != nil {
		t.Fatalf("CheckText rejected unzoned MTU 9000: %v", err)
	}
}
