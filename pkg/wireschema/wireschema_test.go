package wireschema

import (
	"slices"
	"testing"
)

// #17137 fold: WireNamesOf previously claimed to mirror encoding/json
// exactly while implementing only flat tag semantics, and shipped with
// no test of its own. These cases pin the narrowed contract documented
// on the package: bare "-" excludes, "-,…" emits the literal key "-",
// an empty tag name falls back to the Go field name, unexported fields
// are skipped, and struct/pointer/non-struct inputs behave as
// documented. Embedded-field promotion and duplicate-name dominance
// are deliberately out of scope (see the package doc).
func TestWireNamesOfTagSemantics17137(t *testing.T) {
	type flat struct {
		BareExcluded     int `json:"-"`
		BareName         int `json:"bare"`
		DashOmitEmpty    int `json:"-,omitempty"`
		DashString       int `json:"-,string"`
		EmptyName        int `json:",omitempty"`
		NoTag            int
		EmptyTag         int `json:""`
		unexportedTagged int `json:"unexported"`
		unexported       int
	}
	// Both dash-option fields emit "-": encoding/json (and this
	// extractor) treat "-" before a comma as the NAME, not an
	// exclusion, so the duplicate is intentional evidence of the
	// `-,string` case and must not be "fixed" to a single entry.
	want := []string{"bare", "-", "-", "EmptyName", "NoTag", "EmptyTag"}

	tests := []struct {
		name   string
		sample any
		want   []string
	}{
		{"struct value", flat{}, want},
		{"pointer to struct", &flat{}, want},
		{"double pointer to struct", func() any { s := flat{}; p := &s; return &p }(), want},
		{"nil pointer to struct", (*flat)(nil), want},
		{"non-struct int", 42, nil},
		{"non-struct string", "bare", nil},
		{"non-struct map", map[string]int{}, nil},
		{"non-struct slice", []int{}, nil},
		{"nil sample", nil, nil},
		{"pointer to non-struct", new(int), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := WireNamesOf(tc.sample); !slices.Equal(got, tc.want) {
				t.Fatalf("WireNamesOf(%T) = %q, want %q (#17137)", tc.sample, got, tc.want)
			}
		})
	}
}
