package config

import "testing"

// #14428 (DR16-H7): RA prefix packed tail whose first head is a flag.

func raPrefixCompileForTest(t *testing.T, src string, lenient bool) *RAPrefix {
	t.Helper()
	compile := CompileConfig
	if lenient {
		compile = CompileConfigLenient
	}
	cfg, err := compile(hierTree(t, src))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, ra := range cfg.Protocols.RouterAdvertisement {
		if ra != nil && ra.Interface == "ge-0/0/0.0" {
			if len(ra.Prefixes) != 1 {
				t.Fatalf("prefixes = %+v, want exactly 1", ra.Prefixes)
			}
			return ra.Prefixes[0]
		}
	}
	t.Fatal("no RA prefix compiled")
	return nil
}

func TestRAPrefixPackedFlagsDR16H7(t *testing.T) {
	braced := `
protocols {
    router-advertisement {
        interface ge-0/0/0.0 {
            prefix 2001:db8::/64 {
                no-autonomous;
                no-onlink;
                valid-lifetime 100;
                preferred-lifetime 50;
            }
        }
    }
}
`
	want := raPrefixCompileForTest(t, braced, false)
	if want.OnLink || want.Autonomous || want.ValidLifetime != 100 || want.PreferredLife != 50 {
		t.Fatalf("braced control wrong: %+v", want)
	}
	cases := []struct {
		name       string
		tail       string
		wantOnLink bool
	}{
		{"no-autonomous first", "no-autonomous no-onlink valid-lifetime 100 preferred-lifetime 50", false},
		{"no-onlink first", "no-onlink no-autonomous valid-lifetime 100 preferred-lifetime 50", false},
		{"only no-autonomous packed", "no-autonomous valid-lifetime 100 preferred-lifetime 50", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `
protocols {
    router-advertisement {
        interface ge-0/0/0.0 {
            prefix 2001:db8::/64 ` + tc.tail + `;
        }
    }
}
`
			for _, lenient := range []bool{false, true} {
				got := raPrefixCompileForTest(t, src, lenient)
				if got.OnLink != tc.wantOnLink || got.Autonomous != want.Autonomous || got.ValidLifetime != want.ValidLifetime || got.PreferredLife != want.PreferredLife {
					t.Errorf("lenient=%v got %+v want OnLink=%v Autonomous=%v Valid=%d Preferred=%d", lenient, got, tc.wantOnLink, want.Autonomous, want.ValidLifetime, want.PreferredLife)
				}
			}
		})
	}
	// Single flags alone.
	for _, tc := range []struct {
		name string
		tail string
		want *RAPrefix
	}{
		{"no-autonomous alone", "no-autonomous", &RAPrefix{Prefix: "2001:db8::/64", OnLink: true, Autonomous: false}},
		{"no-onlink alone", "no-onlink", &RAPrefix{Prefix: "2001:db8::/64", OnLink: false, Autonomous: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := `
protocols {
    router-advertisement {
        interface ge-0/0/0.0 {
            prefix 2001:db8::/64 ` + tc.tail + `;
        }
    }
}
`
			got := raPrefixCompileForTest(t, src, false)
			if *got != *tc.want {
				t.Errorf("got %+v want %+v", got, tc.want)
			}
		})
	}
	// Flat-set control must stay green.
	t.Run("flat set control", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set protocols router-advertisement interface ge-0/0/0.0 prefix 2001:db8::/64 no-autonomous",
			"set protocols router-advertisement interface ge-0/0/0.0 prefix 2001:db8::/64 no-onlink",
			"set protocols router-advertisement interface ge-0/0/0.0 prefix 2001:db8::/64 valid-lifetime 100",
		)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile flat: %v", err)
		}
		var got *RAPrefix
		for _, ra := range cfg.Protocols.RouterAdvertisement {
			if ra != nil && len(ra.Prefixes) > 0 {
				got = ra.Prefixes[0]
			}
		}
		if got == nil || got.OnLink || got.Autonomous || got.ValidLifetime != 100 {
			t.Errorf("flat control got %+v", got)
		}
	})
	// Mixed: packed tail plus braced body.
	t.Run("mixed packed tail braced body", func(t *testing.T) {
		src := `
protocols {
    router-advertisement {
        interface ge-0/0/0.0 {
            prefix 2001:db8::/64 no-autonomous no-onlink {
                valid-lifetime 100;
            }
        }
    }
}
`
		got := raPrefixCompileForTest(t, src, false)
		if got.OnLink || got.Autonomous || got.ValidLifetime != 100 {
			t.Errorf("mixed got %+v", got)
		}
	})
}
