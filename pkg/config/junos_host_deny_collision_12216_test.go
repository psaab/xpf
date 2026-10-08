package config

import "testing"

func assertHostDenyNotRendered12216(t *testing.T, cfg *Config, source, application string) {
	t.Helper()
	cfg.Security.Policies = []*ZonePairPolicies{{
		FromZone: "untrust",
		ToZone:   "junos-host",
		Policies: []*Policy{{
			Name:   "blocked",
			Action: PolicyDeny,
			Match: PolicyMatch{
				SourceAddresses:      []string{source},
				DestinationAddresses: []string{"any"},
				Applications:         []string{application},
			},
		}},
	}}
	projection := BuildJunosHostDenyProjection(cfg)
	if len(projection.Programs) != 1 || projection.Programs[0].Representable {
		t.Fatalf("ambiguous or dangling host deny must be explicitly unrepresentable: %+v", projection.Programs)
	}
	key := JunosHostZonePairPolicyKey("untrust", "blocked")
	if projection.RenderedPolicyKeys[key] {
		t.Fatalf("unrepresentable host deny must not suppress its policy warning: %+v", projection.RenderedPolicyKeys)
	}
}

func TestJunosHostAddressBookCollisionsAreUnrepresentable12216(t *testing.T) {
	cases := []struct {
		name string
		book *AddressBook
		ref  string
	}{
		{
			name: "direct address-address-set collision",
			book: &AddressBook{
				Addresses: map[string]*Address{
					"blocked": {Name: "blocked", Value: "10.0.0.0/8"},
					"other":   {Name: "other", Value: "192.0.2.1/32"},
				},
				AddressSets: map[string]*AddressSet{
					"blocked": {Name: "blocked", Addresses: []string{"other"}},
				},
				CollidingNames: map[string]struct{}{"blocked": {}},
			},
			ref: "blocked",
		},
		{
			name: "nested address-set collision",
			book: &AddressBook{
				Addresses: map[string]*Address{
					"blocked": {Name: "blocked", Value: "10.0.0.0/8"},
					"other":   {Name: "other", Value: "192.0.2.1/32"},
				},
				AddressSets: map[string]*AddressSet{
					"blocked": {Name: "blocked", Addresses: []string{"other"}},
					"outer":   {Name: "outer", AddressSets: []string{"blocked"}},
				},
				CollidingNames: map[string]struct{}{"blocked": {}},
			},
			ref: "outer",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := jhTestConfig()
			cfg.Security.AddressBook = tc.book
			v4, v6, _, _, ok := junosHostResolveAddrSet(cfg, []string{tc.ref}, nil)
			if ok {
				t.Fatalf("host projection accepted colliding reference %q: v4=%v v6=%v", tc.ref, v4, v6)
			}
			term := junosHostProjectTerm(cfg, "deny", &Policy{
				Action: PolicyDeny,
				Match: PolicyMatch{
					SourceAddresses:      []string{tc.ref},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
				},
			}, nil)
			if term.representable {
				t.Fatalf("host deny projection represented colliding reference %q", tc.ref)
			}

			assertHostDenyNotRendered12216(t, cfg, tc.ref, "any")
		})
	}
}

func TestJunosHostDanglingAddressSetIsUnrepresentable12216(t *testing.T) {
	cfg := jhTestConfig()
	cfg.Security.AddressBook = &AddressBook{
		Addresses: map[string]*Address{
			"good": {Name: "good", Value: "10.20.0.0/16"},
		},
		AddressSets: map[string]*AddressSet{
			"mixed": {Name: "mixed", Addresses: []string{"good", "ghost"}},
		},
	}
	v4, _, _, _, ok := junosHostResolveAddrSet(cfg, []string{"mixed"}, nil)
	if ok {
		t.Fatalf("host projection accepted a dangling set's surviving subset: v4=%v", v4)
	}
	term := junosHostProjectTerm(cfg, "deny", &Policy{
		Action: PolicyDeny,
		Match: PolicyMatch{
			SourceAddresses:      []string{"mixed"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
		},
	}, nil)
	if term.representable {
		t.Fatal("host deny projection represented a set with a dangling member")
	}
	assertHostDenyNotRendered12216(t, cfg, "mixed", "any")
}

func TestJunosHostApplicationCollisionsAreUnrepresentable12216(t *testing.T) {
	cases := []struct {
		name string
		apps ApplicationsConfig
		ref  string
	}{
		{
			name: "direct application-application-set collision",
			apps: ApplicationsConfig{
				Applications: map[string]*Application{
					"web": {Name: "web", Protocol: "tcp", DestinationPort: "80"},
				},
				ApplicationSets: map[string]*ApplicationSet{
					"web": {Name: "web", Applications: []string{"junos-https"}},
				},
				CollidingNames: map[string]struct{}{"web": {}},
			},
			ref: "web",
		},
		{
			name: "nested application-set collision",
			apps: ApplicationsConfig{
				Applications: map[string]*Application{
					"tcp-web": {Name: "tcp-web", Protocol: "tcp", DestinationPort: "80"},
				},
				ApplicationSets: map[string]*ApplicationSet{
					"ambiguous": {Name: "ambiguous", Applications: []string{"tcp-web"}},
					"outer":     {Name: "outer", Applications: []string{"ambiguous"}},
				},
				CollidingNames: map[string]struct{}{"ambiguous": {}},
			},
			ref: "outer",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := jhTestConfig()
			cfg.Applications = tc.apps
			l4, appAny, ok := junosHostResolveApplications(cfg, []string{tc.ref})
			if ok || appAny || len(l4) != 0 {
				t.Fatalf("host projection accepted collision %q: l4=%+v appAny=%v ok=%v", tc.ref, l4, appAny, ok)
			}
			assertHostDenyNotRendered12216(t, cfg, "any", tc.ref)
		})
	}
}
