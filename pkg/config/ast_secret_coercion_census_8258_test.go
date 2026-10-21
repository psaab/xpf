package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// #8258 starting point 3, and the hole it found in starting point 1.
//
// `ast_secret_redaction_census_8258_test.go` enumerates its population by
// REFLECTION over `Secret`-typed fields, and its commit argued that reflection
// beats the source scan #8104 had to use because "the population is a TYPE, so
// reflection enumerates it exactly. No wrapper can hide from it."
//
// That was wrong in a specific way, and #8258's own starting point 3 —
// "anything with a `MarshalJSON` that transforms a value" — is what surfaced
// it. `SNMPCommunity.Name` is declared `string`. It becomes a `Secret` only
// inside `MarshalJSON`/`MarshalYAML`, by conversion:
//
//	return json.Marshal(alias{Name: NewSecret(c.Name), ...})
//
// So the typed route DOES redact it, exactly as if the field were declared
// `Secret` — and the reflection census cannot see it, because at the type level
// the field is a plain string. The SNMP v1/v2c community string is the
// v1/v2c AUTHENTICATOR, so this is not an obscure corner.
//
// This is the identical trap #8104's own census comment records and warns
// about, arriving from the other direction:
//
//	"defining a set as 'things that call X' is a CLAIM that X is the only
//	route to the behaviour."
//
// Defining a set as "things whose TYPE is X" is the same claim. A conversion is
// a route to the behaviour that the type does not record. Reflection is exact
// about the question it answers; the error was in believing that question was
// the whole population.
//
// This file closes the gap by enumerating the OTHER route with `go/ast` rather
// than a regex — a conversion `NewSecret(x.F)` inside a method is a syntactic
// fact, so it can be extracted precisely instead of pattern-matched. Both
// censuses feed the same map, so a leaf enrolled by either route is verified
// the same way.

// secretCoercionCensus parses the config package and returns every
// "TypeName.FieldName" that is CONVERTED to `Secret` inside a method, which is
// how a field that is not declared `Secret` still redacts on the typed route.
//
// Scoped to method bodies with a receiver so the result can be reported as
// Type.Field, matching the reflection census's vocabulary. A conversion of
// something that is not a plain field selector on the receiver (a local, a
// literal, a nested expression) is not reported — those cannot be named in the
// same vocabulary, and the completeness check below is what catches one
// appearing.
func secretCoercionCensus(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var found []string
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			recvType := receiverTypeName(fn.Recv.List[0].Type)
			if recvType == "" || recvType == "Secret" {
				// Secret's own methods convert to and from itself; that is the
				// mechanism, not a use of it.
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				// #15990 fold: Secret is no longer a string kind, so the
				// coercion form is the constructor call NewSecret(x.F)
				// (and, in packages that qualify it, config.NewSecret).
				// The pre-codemod conversion spelling Secret(x.F) is gone;
				// match the constructor that now performs the coercion.
				ident, ok := call.Fun.(*ast.Ident)
				if !ok || (ident.Name != "NewSecret" && ident.Name != "Secret") {
					return true
				}
				sel, ok := call.Args[0].(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if _, ok := sel.X.(*ast.Ident); !ok {
					return true
				}
				found = append(found, recvType+"."+sel.Sel.Name)
				return true
			})
		}
	}

	// POSITIVE CONTROL on the scan itself. A parse that reached no files, or a
	// package layout change, would return an empty set — and an empty set makes
	// every assertion below pass while enumerating nothing.
	if scanned < 20 {
		t.Fatalf("the scan parsed only %d non-test files in pkg/config; that is not "+
			"this package, so the census enumerated nothing and would pass vacuously",
			scanned)
	}

	sort.Strings(found)
	uniq := found[:0]
	var last string
	for _, s := range found {
		if s != last {
			uniq = append(uniq, s)
			last = s
		}
	}
	return uniq
}

func receiverTypeName(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.StarExpr:
		return receiverTypeName(v.X)
	}
	return ""
}

// TestEverySecretCoercionIsMapped is the second half of the #8258 population.
//
// A field CONVERTED to `Secret` on the typed route redacts there exactly as a
// field DECLARED `Secret` does, so it owes the same AST-route agreement. The
// reflection census cannot enrol it; this one does, into the same map, so the
// behavioural verdict covers both routes with one implementation.
func TestEverySecretCoercionIsMapped(t *testing.T) {
	coerced := secretCoercionCensus(t)

	// The scan must find the known instance. Without this the whole file could
	// silently stop matching — a refactor of the conversion into a helper, a
	// renamed receiver — and report a clean census over an empty set. This is
	// the assertion the reflection census lacked, which is why it shipped
	// blind to this route in the first place.
	const known = "SNMPCommunity.Name"
	if !containsString(coerced, known) {
		t.Fatalf("the coercion scan did not find %s, which is the instance this file "+
			"exists for (types_system.go converts it inside MarshalJSON and "+
			"MarshalYAML). Found: %v.\n\nThe scan is broken, not the tree — a clean "+
			"result here would mean nothing.", known, coerced)
	}

	for _, field := range coerced {
		if _, ok := astLeafForSecretField[field]; !ok {
			t.Errorf("%s is CONVERTED to `Secret` on the typed route, so the JSON/REST "+
				"config surface redacts it — but this census has no entry for it, so "+
				"nothing checks whether `show configuration` and the gRPC config RPCs "+
				"redact the same value.\n\n"+
				"Its type is not `Secret`, so the reflection census in "+
				"ast_secret_redaction_census_8258_test.go cannot see it. Add an entry to "+
				"astLeafForSecretField with the `set` command that populates the leaf.",
				field)
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
