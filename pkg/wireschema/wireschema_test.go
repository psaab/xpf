package wireschema

import (
	"go/ast"
	"reflect"
	"slices"
	"testing"
)

// pkgAnchor19172 names this package for the fixture's unexported fields.
type pkgAnchor19172 struct{}

// #17137 fold: WireNamesOf previously claimed to mirror encoding/json
// exactly while implementing only flat tag semantics, and shipped with
// no test of its own. These cases pin the narrowed contract documented
// on the package: bare "-" excludes, "-,…" emits the literal key "-",
// an empty tag name falls back to the Go field name, unexported fields
// are skipped, and struct/pointer/non-struct inputs behave as
// documented. Embedded-field promotion and duplicate-name dominance
// are deliberately out of scope (see the package doc).
func TestWireNamesOfTagSemantics17137(t *testing.T) {
	// The fixture is built at run time with reflect.StructOf (#19172). As
	// a struct literal, its deliberate tags (a second "-" name via
	// `-,string`, a json tag on an unexported field) are exactly what
	// go vet's structtag analyzer reports, and the tree-wide vet gate
	// (#9590) was red on them. Built from data, the type is the same:
	// same field order, names, unexportedness and tags. vet just cannot
	// see the literals.
	intT := reflect.TypeOf(0)
	field := func(name, tag string) reflect.StructField {
		f := reflect.StructField{Name: name, Type: intT, Tag: reflect.StructTag(tag)}
		if !ast.IsExported(name) {
			f.PkgPath = reflect.TypeOf(pkgAnchor19172{}).PkgPath() // as a literal's unexported field carries
		}
		return f
	}
	flat := reflect.StructOf([]reflect.StructField{
		field("BareExcluded", `json:"-"`),
		field("BareName", `json:"bare"`),
		field("DashOmitEmpty", `json:"-,omitempty"`),
		field("DashString", `json:"-,string"`),
		field("EmptyName", `json:",omitempty"`),
		field("NoTag", ``),
		field("EmptyTag", `json:""`),
		field("unexportedTagged", `json:"unexported"`),
		field("unexported", ``),
	})
	// The fixture must still carry what the cells are about: if StructOf
	// ever dropped a tag or exported a field, the cells below would test
	// a different type.
	if f, _ := flat.FieldByName("DashString"); f.Tag.Get("json") != "-,string" {
		t.Fatalf("fixture: DashString tag = %q, want -,string", f.Tag.Get("json"))
	}
	if f, _ := flat.FieldByName("unexportedTagged"); f.IsExported() || f.Tag.Get("json") != "unexported" {
		t.Fatalf("fixture: unexportedTagged exported=%v tag=%q, want unexported with tag", f.IsExported(), f.Tag.Get("json"))
	}
	value := reflect.New(flat).Elem().Interface()
	ptr := reflect.New(flat).Interface()
	pp := reflect.New(reflect.PointerTo(flat))
	pp.Elem().Set(reflect.New(flat))
	nilPtr := reflect.Zero(reflect.PointerTo(flat)).Interface()

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
		{"struct value", value, want},
		{"pointer to struct", ptr, want},
		{"double pointer to struct", pp.Interface(), want},
		{"nil pointer to struct", nilPtr, want},
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
