package cli

import "testing"

// #14688: local showInterfaces must reject post-selector modifiers and
// surplus args instead of ignoring them.
func TestShowInterfacesRejectsPostDynamic14688(t *testing.T) {
	c := &CLI{}
	for _, args := range [][]string{
		{"ge-0/0/0", "terse"},
		{"ge-0/0/0", "statistics"},
		{"ge-0/0/0", "queue", "detail"},
		{"ge-0/0/0", "bogus"},
		{"ge-0/0/0", "detail", "extensive"},
		{"ge-0/0/0", "detail", "junk"},
		{"queue", "ge-0/0/0", "detail"},
		{"terse", "ge-0/0/0"},
	} {
		if err := c.showInterfaces(args); err == nil {
			t.Errorf("showInterfaces(%q) = nil, want rejection", args)
		}
	}
}
