package config

import (
	"reflect"
	"testing"
)

// #16160 (schema R1): ProvideValues is the single shared live-value
// completion switch for pkg/cli and pkg/grpcapi, and HintRoots is the
// shared hint-roots table both authz wrappers consult. The fixture
// carries present-but-nil zone/interface/unit/zone-pair/policy slots
// (the #3494 tolerant / HA-sync shape), so driving every hint proves no
// nil-slot panic and the expected names on the one true implementation.
// Assertions canonicalize order (sort by Name, then Desc) because the
// provider iterates maps whose order is unspecified; sorting here pins
// the SET of candidates, never a map-iteration accident.

func completionValuesFixture16160() *Config {
	return &Config{
		Security: SecurityConfig{
			Zones: map[string]*ZoneConfig{
				"trust":   {Name: "trust", Description: "Trust zone"},
				"untrust": {Name: "untrust"},
				"nilzone": nil,
			},
			AddressBook: &AddressBook{
				Addresses: map[string]*Address{
					"host-a": {Name: "host-a", Value: "10.0.0.1/32"},
				},
				AddressSets: map[string]*AddressSet{
					"set-a": {Name: "set-a"},
				},
			},
			NAT: NATConfig{
				SourcePools: map[string]*NATPool{
					"pool-src": {Name: "pool-src"},
				},
				Destination: &DestinationNATConfig{
					Pools: map[string]*NATPool{
						"pool-dst": {Name: "pool-dst"},
					},
				},
			},
			Screen: map[string]*ScreenProfile{
				"scr": {Name: "scr"},
			},
			Log: LogConfig{
				Streams: map[string]*SyslogStream{
					"stream1": {Name: "stream1"},
				},
			},
			Policies: []*ZonePairPolicies{
				nil,
				{
					FromZone: "trust", ToZone: "untrust",
					Policies: []*Policy{
						nil,
						{Name: "allow-web", Description: "Web"},
						{Name: "deny-all"},
					},
				},
			},
			GlobalPolicies: []*Policy{
				nil,
				{Name: "global-pol"},
			},
		},
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/0": {
					Name:        "ge-0/0/0",
					Description: "Uplink",
					Units: map[int]*InterfaceUnit{
						0: {Number: 0, Description: "Primary"},
						1: {Number: 1},
						9: nil,
					},
				},
				"ge-0/0/9": nil,
			},
		},
		Applications: ApplicationsConfig{
			Applications: map[string]*Application{
				"custom-app": {Name: "custom-app", Description: "Custom"},
			},
			ApplicationSets: map[string]*ApplicationSet{
				"custom-set": {Name: "custom-set"},
			},
		},
	}
}

func completionNames16160(in []SchemaCompletion) map[string]string {
	out := make(map[string]string, len(in))
	for _, c := range in {
		out[c.Name] = c.Desc
	}
	return out
}

func TestProvideValuesAllHintsNilFixture16160(t *testing.T) {
	cfg := completionValuesFixture16160()

	cells := []struct {
		name  string
		hint  ValueHint
		path  []string
		names map[string]string // name -> desc
	}{
		{"zone", ValueHintZoneName, nil, map[string]string{"trust": "Trust zone", "untrust": "(configured)"}},
		{"address", ValueHintAddressName, nil, map[string]string{"host-a": "10.0.0.1/32", "set-a": "address-set"}},
		{"pool", ValueHintPoolName, nil, map[string]string{"pool-src": "source pool", "pool-dst": "destination pool"}},
		{"screen", ValueHintScreenProfile, nil, map[string]string{"scr": "screen profile"}},
		{"stream", ValueHintStreamName, nil, map[string]string{"stream1": "log stream"}},
		{"interface", ValueHintInterfaceName, nil, map[string]string{"ge-0/0/0": "Uplink"}},
		{"policy-address", ValueHintPolicyAddress, nil, map[string]string{
			"any": "Any IPv4 or IPv6 address", "any-ipv4": "Any IPv4 address", "any-ipv6": "Any IPv6 address",
			"host-a": "10.0.0.1/32", "set-a": "address-set",
		}},
		{"policy-name-zonepair", ValueHintPolicyName,
			[]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"},
			map[string]string{"allow-web": "Web", "deny-all": "(configured)"}},
		{"policy-name-global", ValueHintPolicyName,
			[]string{"security", "policies", "global", "policy"},
			map[string]string{"global-pol": "(configured)"}},
		{"unit", ValueHintUnitNumber,
			[]string{"interfaces", "ge-0/0/0", "unit"},
			map[string]string{"0": "Primary", "1": "(configured)"}},
	}
	for _, cell := range cells {
		t.Run(cell.name, func(t *testing.T) {
			got := ProvideValues(cfg, cell.hint, cell.path, false)
			if names := completionNames16160(got); !reflect.DeepEqual(names, cell.names) {
				t.Errorf("ProvideValues(%v) = %v, want names %v", cell.hint, got, cell.names)
			}
		})
	}

	// Unit-number against a present-but-nil interface returns nil, and
	// against a missing interface / path returns nil — never a panic.
	for _, path := range [][]string{
		{"interfaces", "ge-0/0/9", "unit"},
		{"interfaces", "missing", "unit"},
		{"interfaces"},
		nil,
	} {
		if got := ProvideValues(cfg, ValueHintUnitNumber, path, false); got != nil {
			t.Errorf("ProvideValues(UnitNumber, %v) = %v, want nil", path, got)
		}
	}
}

func TestProvideValuesSuppressionParity16160(t *testing.T) {
	cfg := completionValuesFixture16160()

	// Suppressed: only configured values; no predefined apps/sets, no
	// PolicyApp "any" literal.
	suppressed := map[ValueHint]map[string]string{
		ValueHintAppName:    {"custom-app": "Custom", "custom-set": "application-set"},
		ValueHintAppSetName: {"custom-set": "application-set"},
		ValueHintPolicyApp:  {"custom-app": "Custom", "custom-set": "application-set"},
	}
	for hint, want := range suppressed {
		if names := completionNames16160(ProvideValues(cfg, hint, nil, true)); !reflect.DeepEqual(names, want) {
			t.Errorf("ProvideValues(%v, suppressed) = %v, want %v", hint, names, want)
		}
	}

	// Unsuppressed: the predefined catalogue appears — every predefined
	// application as "predefined", every predefined application-set as
	// "predefined application-set" (deduplicated), plus PolicyApp "any".
	appNames := completionNames16160(ProvideValues(cfg, ValueHintAppName, nil, false))
	for name := range PredefinedApplications {
		if appNames[name] != "predefined" {
			t.Errorf("AppName unsuppressed missing predefined app %q (desc %q)", name, appNames[name])
		}
	}
	for name := range PredefinedApplicationSets {
		if appNames[name] != "predefined application-set" && appNames[name] != "application-set" {
			t.Errorf("AppName unsuppressed missing predefined set %q (desc %q)", name, appNames[name])
		}
	}
	if appNames["custom-app"] != "Custom" || appNames["custom-set"] != "application-set" {
		t.Errorf("AppName unsuppressed lost configured values: %v", appNames)
	}
	polApp := completionNames16160(ProvideValues(cfg, ValueHintPolicyApp, nil, false))
	if polApp["any"] != "Any application" {
		t.Errorf("PolicyApp unsuppressed missing \"any\": %v", polApp)
	}
	appSetNames := completionNames16160(ProvideValues(cfg, ValueHintAppSetName, nil, false))
	for name := range PredefinedApplicationSets {
		if _, ok := appSetNames[name]; !ok {
			t.Errorf("AppSetName unsuppressed missing predefined set %q", name)
		}
	}
}

func TestProvideValuesNilAndUnknown16160(t *testing.T) {
	cfg := completionValuesFixture16160()
	hints := []ValueHint{
		ValueHintZoneName, ValueHintAddressName, ValueHintAppName, ValueHintPoolName,
		ValueHintInterfaceName, ValueHintScreenProfile, ValueHintStreamName,
		ValueHintAppSetName, ValueHintUnitNumber, ValueHintPolicyAddress,
		ValueHintPolicyApp, ValueHintPolicyName,
	}
	for _, hint := range hints {
		if got := ProvideValues(nil, hint, []string{"interfaces", "ge-0/0/0", "unit"}, false); got != nil {
			t.Errorf("ProvideValues(nil, %v) = %v, want nil", hint, got)
		}
	}
	for _, hint := range []ValueHint{ValueHintNone, ValueHint(999)} {
		if got := ProvideValues(cfg, hint, nil, false); got != nil {
			t.Errorf("ProvideValues(cfg, %v) = %v, want nil", hint, got)
		}
	}
	// Empty (non-nil) config: no panic and no CONFIG-DERIVED values.
	// Catalogue/literal-only hints still offer their non-config data
	// when unsuppressed (predefined apps/sets, PolicyAddress literals,
	// PolicyApp "any") — that is the pre-share behaviour, not a leak.
	empty := &Config{}
	for _, hint := range hints {
		got := ProvideValues(empty, hint, nil, false)
		switch hint {
		case ValueHintPolicyAddress:
			if len(got) != 3 {
				t.Errorf("ProvideValues(empty, PolicyAddress) = %v, want 3 literals", got)
			}
		case ValueHintAppName:
			if want := len(PredefinedApplications) + len(PredefinedApplicationSets); len(got) != want {
				t.Errorf("ProvideValues(empty, AppName) = %d values, want catalogue-only %d", len(got), want)
			}
		case ValueHintAppSetName:
			if len(got) != len(PredefinedApplicationSets) {
				t.Errorf("ProvideValues(empty, AppSetName) = %d values, want catalogue-only %d", len(got), len(PredefinedApplicationSets))
			}
		case ValueHintPolicyApp:
			if want := 1 + len(PredefinedApplications) + len(PredefinedApplicationSets); len(got) != want {
				t.Errorf("ProvideValues(empty, PolicyApp) = %d values, want catalogue-only %d", len(got), want)
			}
		default:
			if len(got) != 0 {
				t.Errorf("ProvideValues(empty, %v) = %v, want empty", hint, got)
			}
		}
		// Suppressed, an empty config offers nothing at all.
		if got := ProvideValues(empty, hint, nil, true); hint != ValueHintPolicyAddress && len(got) != 0 {
			t.Errorf("ProvideValues(empty, %v, suppressed) = %v, want empty", hint, got)
		}
	}
}

func TestHintRootsCoversAllHints16160(t *testing.T) {
	want := map[ValueHint][]string{
		ValueHintZoneName:      {"security zones"},
		ValueHintAddressName:   {"security address-book"},
		ValueHintAppName:       {"applications"},
		ValueHintAppSetName:    {"applications"},
		ValueHintPoolName:      {"security nat"},
		ValueHintInterfaceName: {"interfaces"},
		ValueHintScreenProfile: {"security screen"},
		ValueHintStreamName:    {"security log"},
		ValueHintPolicyAddress: {"security address-book"},
		ValueHintPolicyApp:     {"applications"},
		ValueHintPolicyName:    {"security policies"},
		ValueHintUnitNumber:    {"interfaces"},
	}
	if !reflect.DeepEqual(HintRoots, want) {
		t.Errorf("HintRoots = %v, want %v", HintRoots, want)
	}
	// Every non-None hint the schema can emit is in the table so the
	// frontends' unknown-hint fail-closed arm never fires spuriously.
	for hint := ValueHintZoneName; hint <= ValueHintPolicyName; hint++ {
		if _, ok := HintRoots[hint]; !ok {
			t.Errorf("HintRoots missing hint %v", hint)
		}
	}
	if _, ok := HintRoots[ValueHintNone]; ok {
		t.Errorf("HintRoots must not contain ValueHintNone")
	}
}
