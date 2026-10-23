package config

import (
	"reflect"
	"testing"
)

// #16146: property test for the unified NAT undefined-zone predicate.
// #16008 extends the walk to static-NAT from-zone.
//
// strict-rejected <=> offenders non-empty <=> skip-set exact, across the
// table below. The three projections must agree because they now derive
// from the single natUndefinedZoneFindings walk:
//
//   - strict: validateNATUndefinedZoneStrict errors iff len(offenders)>0,
//     and its message is exactly offenders[0] (per-field, source
//     from -> to -> destination from -> static from order);
//   - tolerant skip-set: NATUndefinedZoneRuleSets contains exactly the
//     distinct {Kind,Name} refs that appear in offenders (per rule-set:
//     a source rule-set with BOTH zones undefined yields two offenders
//     but one skip entry);
//   - kind separation: a source, destination, and static rule-set
//     sharing a name are distinct refs.
//
// FAIL-ON-REVERT: restoring the two independent walks (or collapsing
// per-field granularity into a per-rule-set boolean) breaks at least
// the both-zones cell (offender count / first message) or the
// same-name cell (skip-set cardinality); removing the static arm
// breaks the static cells.
func TestNATUndefinedZoneUnifiedProjections16146(t *testing.T) {
	cases := []struct {
		name       string
		cfg        *Config
		wantOff    []string
		wantSkip   map[NATRuleSetRef]bool
		wantStrict bool
	}{
		{
			name: "nil config",
			cfg:  nil,
		},
		{
			name: "no zones no nat",
			cfg:  &Config{},
		},
		{
			name: "defined zones",
			cfg: &Config{Security: SecurityConfig{
				Zones: map[string]*ZoneConfig{"trust": {}, "untrust": {}},
				NAT: NATConfig{
					Source: []*NATRuleSet{{Name: "ok", FromZone: "trust", ToZone: "untrust"}},
					Destination: &DestinationNATConfig{RuleSets: []*NATRuleSet{
						{Name: "dok", FromZone: "untrust"},
					}},
				},
			}},
		},
		{
			name: "unscoped empty zones are not offenders",
			cfg: &Config{Security: SecurityConfig{
				NAT: NATConfig{
					Source:      []*NATRuleSet{{Name: "global"}},
					Destination: &DestinationNATConfig{RuleSets: []*NATRuleSet{{Name: "dglobal"}}},
				},
			}},
		},
		{
			name: "source from only",
			cfg: &Config{Security: SecurityConfig{
				Zones: map[string]*ZoneConfig{"untrust": {}},
				NAT: NATConfig{Source: []*NATRuleSet{
					{Name: "s1", FromZone: "untrsut", ToZone: "untrust"},
				}},
			}},
			wantOff: []string{`source-nat rule-set "s1": from-zone "untrsut" not defined`},
			wantSkip: map[NATRuleSetRef]bool{
				{Kind: "source", Name: "s1"}: true,
			},
			wantStrict: true,
		},
		{
			name: "source both zones undefined yields two offenders one skip",
			cfg: &Config{Security: SecurityConfig{
				NAT: NATConfig{Source: []*NATRuleSet{
					{Name: "s1", FromZone: "bad-from", ToZone: "bad-to"},
				}},
			}},
			wantOff: []string{
				`source-nat rule-set "s1": from-zone "bad-from" not defined`,
				`source-nat rule-set "s1": to-zone "bad-to" not defined`,
			},
			wantSkip: map[NATRuleSetRef]bool{
				{Kind: "source", Name: "s1"}: true,
			},
			wantStrict: true,
		},
		{
			name: "destination from",
			cfg: &Config{Security: SecurityConfig{
				NAT: NATConfig{Destination: &DestinationNATConfig{RuleSets: []*NATRuleSet{
					{Name: "d1", FromZone: "nope"},
				}}},
			}},
			wantOff: []string{`destination-nat rule-set "d1": from-zone "nope" not defined`},
			wantSkip: map[NATRuleSetRef]bool{
				{Kind: "destination", Name: "d1"}: true,
			},
			wantStrict: true,
		},
		{
			name: "source before destination order and same name distinct kinds",
			cfg: &Config{Security: SecurityConfig{
				NAT: NATConfig{
					Source: []*NATRuleSet{{Name: "shared", ToZone: "bad-to"}},
					Destination: &DestinationNATConfig{RuleSets: []*NATRuleSet{
						{Name: "shared", FromZone: "bad-from"},
					}},
				},
			}},
			wantOff: []string{
				`source-nat rule-set "shared": to-zone "bad-to" not defined`,
				`destination-nat rule-set "shared": from-zone "bad-from" not defined`,
			},
			wantSkip: map[NATRuleSetRef]bool{
				{Kind: "source", Name: "shared"}:      true,
				{Kind: "destination", Name: "shared"}: true,
			},
			wantStrict: true,
		},
		{
			name: "nil rule-sets skipped and healthy sibling excluded",
			cfg: &Config{Security: SecurityConfig{
				Zones: map[string]*ZoneConfig{"trust": {}},
				NAT: NATConfig{
					Source: []*NATRuleSet{nil, {Name: "good", FromZone: "trust"}, {Name: "bad", FromZone: "nope"}},
					Destination: &DestinationNATConfig{RuleSets: []*NATRuleSet{
						nil, {Name: "dgood", FromZone: "trust"},
					}},
				},
			}},
			wantOff: []string{`source-nat rule-set "bad": from-zone "nope" not defined`},
			wantSkip: map[NATRuleSetRef]bool{
				{Kind: "source", Name: "bad"}: true,
			},
			wantStrict: true,
		},
		{
			name: "static from",
			cfg: &Config{Security: SecurityConfig{
				NAT: NATConfig{Static: []*StaticNATRuleSet{
					{Name: "st1", FromZone: "nope"},
				}},
			}},
			wantOff: []string{`static-nat rule-set "st1": from-zone "nope" not defined`},
			wantSkip: map[NATRuleSetRef]bool{
				{Kind: "static", Name: "st1"}: true,
			},
			wantStrict: true,
		},
		{
			name: "static after source and destination, same name distinct kinds",
			cfg: &Config{Security: SecurityConfig{
				NAT: NATConfig{
					Source: []*NATRuleSet{{Name: "shared", FromZone: "bad-s"}},
					Destination: &DestinationNATConfig{RuleSets: []*NATRuleSet{
						{Name: "shared", FromZone: "bad-d"},
					}},
					Static: []*StaticNATRuleSet{{Name: "shared", FromZone: "bad-st"}},
				},
			}},
			wantOff: []string{
				`source-nat rule-set "shared": from-zone "bad-s" not defined`,
				`destination-nat rule-set "shared": from-zone "bad-d" not defined`,
				`static-nat rule-set "shared": from-zone "bad-st" not defined`,
			},
			wantSkip: map[NATRuleSetRef]bool{
				{Kind: "source", Name: "shared"}:      true,
				{Kind: "destination", Name: "shared"}: true,
				{Kind: "static", Name: "shared"}:      true,
			},
			wantStrict: true,
		},
		{
			name: "static unscoped and defined are not offenders, nil skipped",
			cfg: &Config{Security: SecurityConfig{
				Zones: map[string]*ZoneConfig{"trust": {}},
				NAT: NATConfig{Static: []*StaticNATRuleSet{
					nil, {Name: "global"}, {Name: "good", FromZone: "trust"},
				}},
			}},
		},
		{
			name: "nil destination config",
			cfg: &Config{Security: SecurityConfig{
				NAT: NATConfig{Source: []*NATRuleSet{{Name: "s", FromZone: "x"}}},
			}},
			wantOff: []string{`source-nat rule-set "s": from-zone "x" not defined`},
			wantSkip: map[NATRuleSetRef]bool{
				{Kind: "source", Name: "s"}: true,
			},
			wantStrict: true,
		},
		{
			name: "present but nil zone value still defined",
			cfg: &Config{Security: SecurityConfig{
				Zones: map[string]*ZoneConfig{"trust": nil},
				NAT:   NATConfig{Source: []*NATRuleSet{{Name: "s", FromZone: "trust"}}},
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			offenders := natUndefinedZoneOffenders(tc.cfg)
			if !reflect.DeepEqual(offenders, tc.wantOff) {
				t.Fatalf("offenders = %v, want %v", offenders, tc.wantOff)
			}
			skip := NATUndefinedZoneRuleSets(tc.cfg)
			wantSkip := tc.wantSkip
			if wantSkip == nil {
				wantSkip = map[NATRuleSetRef]bool{}
			}
			if !reflect.DeepEqual(skip, wantSkip) {
				t.Fatalf("skip-set = %v, want %v", skip, wantSkip)
			}
			err := validateNATUndefinedZoneStrict(tc.cfg)
			if tc.wantStrict {
				if err == nil {
					t.Fatalf("strict accepted, want reject; offenders=%v", offenders)
				}
				if err.Error() != tc.wantOff[0] {
					t.Fatalf("strict error = %q, want first offender %q", err.Error(), tc.wantOff[0])
				}
			} else if err != nil {
				t.Fatalf("strict rejected %v, want accept; offenders=%v", err, offenders)
			}
			// Cross-projection invariant, independent of the table:
			// strict-rejected <=> offenders non-empty <=> skip non-empty,
			// and every offender's ref is in the skip-set.
			if (err != nil) != (len(offenders) > 0) || (len(offenders) > 0) != (len(skip) > 0) {
				t.Fatalf("projection disagreement: err=%v offenders=%v skip=%v", err, offenders, skip)
			}
			// Key-check path must not allocate an offender list: the
			// skip projection is built from findings directly. Assert
			// skip cardinality <= offender count (per-field >= per-set).
			if len(skip) > len(offenders) {
				t.Fatalf("skip-set %d larger than offenders %d", len(skip), len(offenders))
			}
		})
	}
}

// TestNATUndefinedZoneStructKeyNoSeparatorCollision16146 pins that the
// struct key cannot collide the way a separator-joined string could if
// kind/name boundaries shifted: refs differing in either field are
// distinct map keys.
func TestNATUndefinedZoneStructKeyNoSeparatorCollision16146(t *testing.T) {
	m := map[NATRuleSetRef]bool{
		{Kind: "source", Name: "a"}:      true,
		{Kind: "destination", Name: "a"}: true,
		{Kind: "source", Name: "b"}:      true,
	}
	if len(m) != 3 {
		t.Fatalf("struct-key map collapsed distinct refs: %v", m)
	}
	if m[NATRuleSetRef{Kind: "source\x00a", Name: ""}] {
		t.Fatal("separator-smuggled ref must not match a real ref")
	}
}
