package config

import "testing"

// #15033 (A03-04): an outer apply-groups beats a nested one, but Junos says
// the more specific (nested/deeper) hierarchy wins. Outer group applied at
// top level sets interface filter to PERMISSIVE; nested group applied at
// interfaces.ge-0/0/0 sets it to STRICT for the same unit. Nested must win,
// while a genuine inline leaf still wins over both.

func findUnit15033(t *testing.T, cfg *Config) *InterfaceUnit {
	t.Helper()
	for _, iface := range cfg.Interfaces.Interfaces {
		if iface.Name == "ge-0/0/0" {
			for _, u := range iface.Units {
				if u.Number == 0 {
					return u
				}
			}
		}
	}
	t.Fatalf("ge-0/0/0 unit 0 not found: %+v", cfg.Interfaces.Interfaces)
	return nil
}

const filters15033 = `
firewall {
    family inet {
        filter PERMISSIVE { term t { then accept; } }
        filter STRICT { term t { then accept; } }
    }
}
`

func TestNestedApplyGroupsBeatsOuter15033(t *testing.T) {
	text := `
groups {
    GLOBAL {
        interfaces {
            ge-0/0/0 {
                unit 0 {
                    family inet {
                        filter { input PERMISSIVE; }
                    }
                }
            }
        }
    }
    HARDEN {
        interfaces {
            ge-0/0/0 {
                unit 0 {
                    family inet {
                        filter { input STRICT; }
                    }
                }
            }
        }
    }
}
apply-groups GLOBAL;
interfaces {
    ge-0/0/0 {
        apply-groups HARDEN;
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
` + filters15033
	cfg, err := CompileConfig(parseTree9422(t, text))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	u := findUnit15033(t, cfg)
	if u.FilterInputV4 != "STRICT" {
		t.Fatalf("nested apply-groups must win over outer: FilterInputV4=%q want STRICT", u.FilterInputV4)
	}
	if len(u.Addresses) == 0 {
		t.Fatalf("inline address lost: %+v", u)
	}
}

func TestNestedApplyGroupsScalarBeatsOuter15033(t *testing.T) {
	text := `
groups {
    GLOBAL { system { host-name OUTER; } }
    HARDEN { system { host-name NESTED; } }
}
apply-groups GLOBAL;
system {
    apply-groups HARDEN;
    domain-name example.com;
}
`
	cfg, err := CompileConfig(parseTree9422(t, text))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.HostName != "NESTED" {
		t.Fatalf("nested scalar must win: HostName=%q want NESTED", cfg.System.HostName)
	}
	if cfg.System.DomainName != "example.com" {
		t.Fatalf("inline domain lost: %q", cfg.System.DomainName)
	}
}

func TestInlineStillBeatsNestedApplyGroups15033(t *testing.T) {
	text := `
groups {
    GLOBAL {
        interfaces { ge-0/0/0 { unit 0 { family inet { filter { input PERMISSIVE; } } } } }
    }
    HARDEN {
        interfaces { ge-0/0/0 { unit 0 { family inet { filter { input STRICT; } } } } }
    }
    INLINEF {
        interfaces { ge-0/0/0 { unit 0 { family inet { filter { input PERMISSIVE; } } } } }
    }
}
apply-groups GLOBAL;
interfaces {
    ge-0/0/0 {
        apply-groups HARDEN;
        unit 0 {
            family inet {
                address 10.0.0.1/24;
                filter { input INLINEF; }
            }
        }
    }
}
firewall {
    family inet {
        filter PERMISSIVE { term t { then accept; } }
        filter STRICT { term t { then accept; } }
        filter INLINEF { term t { then accept; } }
    }
}
`
	cfg, err := CompileConfig(parseTree9422(t, text))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	u := findUnit15033(t, cfg)
	if u.FilterInputV4 != "INLINEF" {
		t.Fatalf("inline must still win over nested group: FilterInputV4=%q want INLINEF", u.FilterInputV4)
	}
}

func TestOuterOnlyApplyGroupsControl15033(t *testing.T) {
	text := `
groups {
    GLOBAL {
        interfaces { ge-0/0/0 { unit 0 { family inet { filter { input PERMISSIVE; } } } } }
    }
}
apply-groups GLOBAL;
interfaces {
    ge-0/0/0 {
        unit 0 { family inet { address 10.0.0.1/24; } }
    }
}
` + filters15033
	cfg, err := CompileConfig(parseTree9422(t, text))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := findUnit15033(t, cfg).FilterInputV4; got != "PERMISSIVE" {
		t.Fatalf("outer-only control: FilterInputV4=%q want PERMISSIVE", got)
	}
}
