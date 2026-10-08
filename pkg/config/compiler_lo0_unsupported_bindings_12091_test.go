package config

import (
	"strconv"
	"strings"
	"testing"
)

const lo0Filters12091 = `firewall {
    family inet {
        filter v4 {
            term t { then accept; }
        }
    }
    family inet6 {
        filter v6 {
            term t { then accept; }
        }
    }
}`

func compileLo0Set12091(t *testing.T, lines ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range append([]string{
		"set firewall family inet filter v4 term t then accept",
		"set firewall family inet6 filter v6 term t then accept",
	}, lines...) {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict flat-set compile: %v", err)
	}
	return cfg
}

func compileLo0Hier12091(t *testing.T, interfaces string) *Config {
	t.Helper()
	tree, errs := NewParser(lo0Filters12091 + interfaces).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse hierarchical config: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict hierarchical compile: %v", err)
	}
	return cfg
}

func requireLo0UnsupportedWarning12091(t *testing.T, cfg *Config, want ...string) {
	t.Helper()
	for _, warning := range cfg.Warnings {
		if !strings.Contains(warning, "#12091") || !strings.Contains(warning, "accepted but NOT enforced") {
			continue
		}
		for _, part := range want {
			if !strings.Contains(warning, part) {
				t.Fatalf("#12091 warning %q is missing %q", warning, part)
			}
		}
		return
	}
	t.Fatalf("missing named accepted-but-NOT-enforced #12091 advisory (wanted %v), cfg.Warnings: %v", want, cfg.Warnings)
}

func TestLo0UnsupportedFilterBindingsWarn12091(t *testing.T) {
	cases := []struct {
		name      string
		unit      int
		family    string
		direction string
		filter    string
		field     string
	}{
		{name: "nonzero inet input", unit: 1, family: "inet", direction: "input", filter: "v4", field: "FilterInputV4"},
		{name: "nonzero inet6 input", unit: 1, family: "inet6", direction: "input", filter: "v6", field: "FilterInputV6"},
		{name: "unit zero inet output", unit: 0, family: "inet", direction: "output", filter: "v4", field: "FilterOutputV4"},
		{name: "unit zero inet6 output", unit: 0, family: "inet6", direction: "output", filter: "v6", field: "FilterOutputV6"},
		{name: "nonzero inet output", unit: 1, family: "inet", direction: "output", filter: "v4", field: "FilterOutputV4"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			unitNumber := strconv.Itoa(tc.unit)
			setLine := "set interfaces lo0 unit " + unitNumber + " family " + tc.family + " filter " + tc.direction + " " + tc.filter
			text := `interfaces { lo0 { unit ` + unitNumber + ` { family ` + tc.family + ` { filter { ` + tc.direction + ` ` + tc.filter + `; } } } } }`
			want := []string{"lo0", "unit " + unitNumber, "family " + tc.family, "filter " + tc.direction, tc.filter}
			for _, shape := range []struct {
				name    string
				compile func(*testing.T) *Config
			}{
				{name: "flat-set", compile: func(t *testing.T) *Config { return compileLo0Set12091(t, setLine) }},
				{name: "hierarchical", compile: func(t *testing.T) *Config { return compileLo0Hier12091(t, text) }},
			} {
				t.Run(shape.name, func(t *testing.T) {
					cfg := shape.compile(t)
					requireLo0UnsupportedWarning12091(t, cfg, want...)
					unit := cfg.Interfaces.Interfaces["lo0"].Units[tc.unit]
					if unit == nil || fieldLo0Filter12091(unit, tc.field) != tc.filter {
						t.Fatalf("binding was unexpectedly lost: unit=%+v field=%s", unit, tc.field)
					}
				})
			}
		})
	}
}

func TestLo0UnitZeroInputFilterRemainsEnforced12091(t *testing.T) {
	flat := compileLo0Set12091(t,
		"set interfaces lo0 unit 0 family inet filter input v4",
		"set interfaces lo0 unit 0 family inet6 filter input v6")
	hier := compileLo0Hier12091(t, `interfaces { lo0 { unit 0 {
    family inet { filter { input v4; } }
    family inet6 { filter { input v6; } }
} } }`)
	for _, cfg := range []*Config{flat, hier} {
		if cfg.System.Lo0FilterInputV4 != "v4" || cfg.System.Lo0FilterInputV6 != "v6" {
			t.Fatalf("supported unit-zero inputs did not populate System fields: v4=%q v6=%q", cfg.System.Lo0FilterInputV4, cfg.System.Lo0FilterInputV6)
		}
		for _, warning := range cfg.Warnings {
			if strings.Contains(warning, "#12091") {
				t.Fatalf("supported unit-zero input unexpectedly warned: %q", warning)
			}
		}
	}
}

func fieldLo0Filter12091(unit *InterfaceUnit, field string) string {
	switch field {
	case "FilterInputV4":
		return unit.FilterInputV4
	case "FilterInputV6":
		return unit.FilterInputV6
	case "FilterOutputV4":
		return unit.FilterOutputV4
	case "FilterOutputV6":
		return unit.FilterOutputV6
	default:
		return ""
	}
}
