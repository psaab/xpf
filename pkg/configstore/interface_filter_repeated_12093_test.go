package configstore

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestLoadOverrideCommitCheckFilterBindingsLastWins12093(t *testing.T) {
	families := []struct {
		name, address string
	}{
		{name: "inet", address: "10.0.0.1/24"},
		{name: "inet6", address: "2001:db8::1/64"},
	}
	directions := []string{"input", "output"}
	forms := []struct {
		name string
		text func(string) string
	}{
		{
			name: "compact repeats",
			text: func(direction string) string {
				return fmt.Sprintf("filter %s A; filter %s B;", direction, direction)
			},
		},
		{
			name: "repeated blocks",
			text: func(direction string) string {
				return fmt.Sprintf("filter { %s A; } filter { %s B; }", direction, direction)
			},
		},
		{
			name: "compact then block",
			text: func(direction string) string {
				return fmt.Sprintf("filter %s A; filter { %s B; }", direction, direction)
			},
		},
		{
			name: "block then compact",
			text: func(direction string) string {
				return fmt.Sprintf("filter { %s A; } filter %s B;", direction, direction)
			},
		},
	}

	for _, family := range families {
		for _, direction := range directions {
			for _, form := range forms {
				t.Run(family.name+"/"+direction+"/"+form.name, func(t *testing.T) {
					compiled := commitCheckFilterBinding12093(t, family.name, family.address, form.text(direction))
					if got := interfaceFilterBinding12093(compiled, family.name, direction); got != "B" {
						t.Fatalf("effective filter = %q, want last binding B", got)
					}
				})
			}
		}
	}
}

func TestLoadOverrideCommitCheckAcceptsSingleChildFilterBlock12093(t *testing.T) {
	families := []struct {
		name, address string
	}{
		{name: "inet", address: "10.0.0.1/24"},
		{name: "inet6", address: "2001:db8::1/64"},
	}
	for _, family := range families {
		for _, direction := range []string{"input", "output"} {
			t.Run(family.name+"/"+direction, func(t *testing.T) {
				binding := fmt.Sprintf("filter { %s { f1; } }", direction)
				compiled := commitCheckFilterBinding12093(t, family.name, family.address, binding)
				if got := interfaceFilterBinding12093(compiled, family.name, direction); got != "f1" {
					t.Fatalf("effective filter = %q, want single-child block value f1", got)
				}
			})
		}
	}
}

func TestCommitCheckRejectsSingleChildScalarGuardCases12093(t *testing.T) {
	cases := []struct {
		name, text, wantError string
	}{
		{
			name: "empty filter value",
			text: `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
                filter { input { ""; } }
            }
        }
    }
}
firewall { family inet { filter f1 { term t1 { then accept; } } } }`,
			wantError: `unexpected trailing token ""`,
		},
		{
			name: "filter sub-statement",
			text: `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
                filter { input { f1 { x; } } }
            }
        }
    }
}
firewall { family inet { filter f1 { term t1 { then accept; } } } }`,
			wantError: "no sub-statement",
		},
		{
			name: "description scope",
			text: `interfaces {
    ge-0/0/0 {
        description { foo; }
        unit 0 { family inet { address 10.0.0.1/24; } }
    }
}`,
			wantError: "no sub-statement",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			commitCheckRejects12093(t, tc.text, tc.wantError)
		})
	}
}

func commitCheckRejects12093(t *testing.T, text, wantError string) {
	t.Helper()
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer s.ExitConfigure()
	if err := s.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := s.CommitCheck(); err == nil {
		t.Fatal("CommitCheck accepted a configuration that must be rejected")
	} else if !strings.Contains(err.Error(), wantError) {
		t.Fatalf("CommitCheck error %q does not contain %q", err, wantError)
	}
}

func commitCheckFilterBinding12093(t *testing.T, family, address, binding string) *config.Config {
	t.Helper()
	text := fmt.Sprintf(`interfaces {
    ge-0/0/0 {
        unit 0 {
            family %s {
                address %s;
                %s
            }
        }
    }
}
firewall {
    family %s {
        filter A { term t1 { then accept; } }
        filter B { term t1 { then accept; } }
        filter f1 { term t1 { then accept; } }
    }
}`, family, address, binding, family)

	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer s.ExitConfigure()
	if err := s.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	compiled, err := s.CommitCheck()
	if err != nil {
		t.Fatalf("CommitCheck: %v", err)
	}
	return compiled
}

func interfaceFilterBinding12093(compiled *config.Config, family, direction string) string {
	iface := compiled.Interfaces.Interfaces["ge-0/0/0"]
	if iface == nil || len(iface.Units) != 1 {
		return ""
	}
	unit := iface.Units[0]
	switch family + " " + direction {
	case "inet input":
		return unit.FilterInputV4
	case "inet output":
		return unit.FilterOutputV4
	case "inet6 input":
		return unit.FilterInputV6
	case "inet6 output":
		return unit.FilterOutputV6
	default:
		return ""
	}
}
