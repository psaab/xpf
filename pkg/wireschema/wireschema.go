// Package wireschema is the single production Go extractor of JSON
// wire names from a struct's json tags (#17137). Its one production
// consumer today is the session-delta schema fingerprint: the daemon
// gate and the parity tests both call WireNamesOf on
// dpuserspace.SessionDeltaInfo.
//
// It lives in this tiny top-level package — not beside the struct in
// pkg/dataplane/userspace, and not in pkg/daemon where the extraction
// used to sit as a second, unguarded copy — because the #1476
// retirement-boundary canary
// (TestUserspaceManagerDoesNotImportReflectOrUnsafe in pkg/dataplane)
// recursively walks pkg/dataplane/userspace (including subpackages)
// and forbids `reflect`/`unsafe` there: reflection is precisely how an
// entry-program canary would be bypassed. pkg/wireschema is outside
// that tree and is reflect-allowed.
//
// The extractor is deliberately generic over the sample value rather
// than naming the parent package's type: an extractor package that
// imported pkg/dataplane/userspace could not be consumed by that
// package's own (internal) tests without an import cycle, which would
// push the tests back onto a private copy — the exact duplication
// #17137 removes. Callers pass the struct value whose tags define the
// schema.
//
// It reads json TAGS, not Go field names: a tag drift breaks the wire
// while leaving both field names untouched, which is the divergence
// class #7194 is about. It implements only the flat field selection
// and tag-name semantics its sole production consumer needs;
// SessionDeltaInfo is a flat struct of exported fields, and that is
// the shape this contract covers:
//
//   - an unexported field is skipped;
//   - a tag whose whole text is "-" excludes the field, while a tag
//     whose name (the part before the first comma) is "-", as in
//     `json:"-,omitempty"` or `json:"-,string"`, emits the key "-";
//   - an empty tag name (or no json tag) falls back to the Go field
//     name;
//   - any other tag name (the part before the first comma) is used
//     verbatim, so options such as ",omitempty" never enter the key.
//
// This is NOT a general encoding/json implementation. It does not
// reproduce encoding/json's embedded-field promotion, its
// duplicate-name dominance rules (depth, then taggedness, then
// declaration order), or its handling of embedded unexported structs:
// an anonymous field is treated like any other field, named by its
// tag or type name, and its fields are not flattened into the
// result. Callers must not feed it types that rely on those rules.
package wireschema

import (
	"reflect"
	"strings"
)

// WireNamesOf returns the JSON wire names of the struct type of sample
// (a struct value or pointer to one), in struct-field order. Callers
// that hash a schema pass the result to a canonicalising hash (for the
// session-delta schema, dpuserspace.SessionDeltaSchemaFingerprintOf,
// which sorts before hashing).
func WireNamesOf(sample any) []string {
	t := reflect.TypeOf(sample)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return nil
	}
	names := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue // unexported: never on the wire
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = f.Name
		}
		names = append(names, name)
	}
	return names
}
