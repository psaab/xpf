package configstore

import "testing"

// #12596 strict-path (CheckText) pin.
func TestCheckTextSamplingElided12596(t *testing.T) {
	cases := []struct {
		name string
		text string
		in   bool
		out  bool
	}{
		{"braced", "interfaces { ge-0/0/0 { unit 0 { family inet { sampling { input; output; } } } } }", true, true},
		{"family elided", "interfaces { ge-0/0/0 { unit 0 { family inet sampling { input; } } } }", true, false},
		{"sampling packed", "interfaces { ge-0/0/0 { unit 0 { family inet { sampling input; } } } }", true, false},
		{"mixed", "interfaces { ge-0/0/0 { unit 0 { family inet { sampling { input; } sampling output; } } } }", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.text, -1)
			if err != nil {
				t.Fatalf("CheckText: %v", err)
			}
			unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
			if unit.SamplingInput != tc.in || unit.SamplingOutput != tc.out {
				t.Errorf("sampling = (%v,%v), want (%v,%v)", unit.SamplingInput, unit.SamplingOutput, tc.in, tc.out)
			}
		})
	}
}
