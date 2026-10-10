package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestInterfaceFilterScalarDuplicatesLastWins12093(t *testing.T) {
	tests := []struct {
		name, family, address, direction string
	}{
		{name: "inet input", family: "inet", address: "10.0.0.1/24", direction: "input"},
		{name: "inet output", family: "inet", address: "10.0.0.1/24", direction: "output"},
		{name: "inet6 input", family: "inet6", address: "2001:db8::1/64", direction: "input"},
		{name: "inet6 output", family: "inet6", address: "2001:db8::1/64", direction: "output"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hier := hierTree(t, fmt.Sprintf(`interfaces {
    ge-0/0/0 {
        unit 0 {
            family %s {
                address %s;
                filter {
                    %s DROP;
                    %s ACCEPT;
                }
            }
        }
    }
}
firewall {
    family %s {
        filter DROP { term t1 { then accept; } }
        filter ACCEPT { term t1 { then accept; } }
    }
}`, tt.family, tt.address, tt.direction, tt.direction, tt.family))
			assertInterfaceFilter12093(t, hier, tt.family, tt.direction, "ACCEPT")

			flat := flatTreeFromSets(t,
				fmt.Sprintf("set interfaces ge-0/0/0 unit 0 family %s address %s", tt.family, tt.address),
				fmt.Sprintf("set interfaces ge-0/0/0 unit 0 family %s filter %s DROP", tt.family, tt.direction),
				fmt.Sprintf("set interfaces ge-0/0/0 unit 0 family %s filter %s ACCEPT", tt.family, tt.direction),
				fmt.Sprintf("set firewall family %s filter DROP term t1 then accept", tt.family),
				fmt.Sprintf("set firewall family %s filter ACCEPT term t1 then accept", tt.family),
			)
			assertInterfaceFilter12093(t, flat, tt.family, tt.direction, "ACCEPT")
		})
	}
}

func TestInterfaceFilterScalarArityGate12093(t *testing.T) {
	tests := []struct {
		name, family, address, direction string
	}{
		{name: "inet input", family: "inet", address: "10.0.0.1/24", direction: "input"},
		{name: "inet output", family: "inet", address: "10.0.0.1/24", direction: "output"},
		{name: "inet6 input", family: "inet6", address: "2001:db8::1/64", direction: "input"},
		{name: "inet6 output", family: "inet6", address: "2001:db8::1/64", direction: "output"},
	}
	for _, tt := range tests {
		for _, hierarchical := range []bool{true, false} {
			form := "flat"
			if hierarchical {
				form = "hierarchical"
			}
			t.Run(tt.name+"/"+form, func(t *testing.T) {
				var tree *ConfigTree
				if hierarchical {
					tree = hierTree(t, fmt.Sprintf(`interfaces {
    ge-0/0/0 {
        unit 0 {
            family %s {
                address %s;
                filter { %s DROP EXTRA; }
            }
        }
    }
}`, tt.family, tt.address, tt.direction))
				} else {
					tree = flatTreeFromSets(t,
						fmt.Sprintf("set interfaces ge-0/0/0 unit 0 family %s address %s", tt.family, tt.address),
						fmt.Sprintf("set interfaces ge-0/0/0 unit 0 family %s filter %s DROP EXTRA", tt.family, tt.direction),
					)
				}
				err := SchemaValidate(tree, nil)
				if err == nil || !strings.Contains(err.Error(), "trailing token") {
					t.Fatalf("expected scalar arity rejection for trailing filter value, got %v", err)
				}
			})
		}
	}
}

func assertInterfaceFilter12093(t *testing.T, tree *ConfigTree, family, direction, want string) {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
	var got string
	switch family + " " + direction {
	case "inet input":
		got = unit.FilterInputV4
	case "inet output":
		got = unit.FilterOutputV4
	case "inet6 input":
		got = unit.FilterInputV6
	case "inet6 output":
		got = unit.FilterOutputV6
	default:
		t.Fatalf("unexpected interface filter %s %s", family, direction)
	}
	if got != want {
		t.Fatalf("%s %s filter = %q, want %q", family, direction, got, want)
	}
}
