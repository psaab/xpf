package config

import "testing"

func TestCompilerStampsImplicitSourceNATScopes12525(t *testing.T) {
	cases := []struct {
		name     string
		from, to []string
		wantFrom bool
		wantTo   bool
	}{
		{
			name:     "fully unscoped",
			wantFrom: true,
			wantTo:   true,
		},
		{
			name:     "explicit from zone and implicit to",
			from:     []string{"set security nat source rule-set RS from zone trust"},
			wantFrom: false,
			wantTo:   true,
		},
		{
			name:     "implicit from and explicit to interface",
			to:       []string{"set security nat source rule-set RS to interface ge-0/0/1.0"},
			wantFrom: true,
			wantTo:   false,
		},
		{
			name: "explicit scopes on both sides",
			from: []string{"set security nat source rule-set RS from interface ge-0/0/0.0"},
			to:   []string{"set security nat source rule-set RS to routing-instance VR1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			commands := append([]string(nil), tc.from...)
			commands = append(commands, tc.to...)
			commands = append(commands,
				"set security nat source rule-set RS rule r1 then source-nat interface")
			cfg, err := CompileConfig(buildNATScopeTree(t, commands...))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			rs := cfg.Security.NAT.Source[0]
			if rs.fromUnscopedStamped != tc.wantFrom || rs.toUnscopedStamped != tc.wantTo {
				t.Fatalf("implicit-scope stamps = from:%t to:%t, want from:%t to:%t",
					rs.fromUnscopedStamped, rs.toUnscopedStamped, tc.wantFrom, tc.wantTo)
			}
		})
	}
}
