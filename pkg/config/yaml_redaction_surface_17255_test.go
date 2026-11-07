package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// #17255: the YAML redaction surface on config types had no encoder or
// decoder in production and covered only part of the JSON redactors, yet
// cost a must-stay-in-sync duplicate of the SNMP alias projection that had
// already picked up a no-op json tag in its YAML copy. The delete arm
// removes every MarshalYAML mirror and yaml struct tag from the config
// types, leaving Secret.MarshalYAML/UnmarshalYAML (secret.go) as the sole
// YAML surface: Secret redacts by type in any encoder and fails closed on
// ingest (#4710), which the hand-kept per-type mirrors did not add to.
//
// This guard keeps the surface deleted. It scans the package AST like
// ast_secret_coercion_census_8258_test.go rather than matching text, so a
// reintroduced mirror is a syntactic fact, not a spelling coincidence.

func TestNoYAMLRedactionSurfaceOutsideSecret17255(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	var violations []string
	snmpAliasDefs := 0
	scanned := 0
	typesScanned := 0
	secretYAMLSeen := false

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
		isTypes := strings.HasPrefix(name, "types") && strings.HasSuffix(name, ".go")

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if name == "secret.go" && fn.Recv != nil &&
				(fn.Name.Name == "MarshalYAML" || fn.Name.Name == "UnmarshalYAML") {
				// Positive control: the scanner does recognise YAML
				// marshalers, so an empty result below cannot be a
				// silently broken scan.
				secretYAMLSeen = true
			}
			if name != "secret.go" && fn.Recv != nil &&
				(fn.Name.Name == "MarshalYAML" || fn.Name.Name == "UnmarshalYAML") {
				violations = append(violations, name+": "+fn.Name.Name+
					" declared outside secret.go (#17255: YAML mirrors on config types are deleted; Secret in secret.go is the only YAML surface)")
			}
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.TypeSpec:
				if node.Name.Name == "snmpAlias" {
					snmpAliasDefs++
				}
			case *ast.Field:
				if isTypes && node.Tag != nil {
					tag := node.Tag.Value
					if unq, err := strconv.Unquote(tag); err == nil {
						tag = unq
					}
					if strings.Contains(tag, "yaml:") {
						violations = append(violations, name+": struct tag contains yaml: ("+tag+")")
					}
				}
			}
			return true
		})
		if isTypes {
			typesScanned++
		}
	}

	// Positive controls on the scan itself, mirroring the census guard: a
	// parse that reached no files would pass vacuously.
	if scanned < 20 {
		t.Fatalf("the scan parsed only %d non-test files in pkg/config; that is not "+
			"this package, so the guard enumerated nothing and would pass vacuously", scanned)
	}
	if typesScanned == 0 {
		t.Fatalf("the scan found no types*.go files in pkg/config; the tag check enumerated nothing")
	}
	if !secretYAMLSeen {
		t.Fatalf("the scan did not find Secret.MarshalYAML/UnmarshalYAML in secret.go, " +
			"which is the sanctioned YAML surface; the scanner is broken, not the tree")
	}

	if snmpAliasDefs != 1 {
		violations = append(violations, "snmpAlias is defined "+strconv.Itoa(snmpAliasDefs)+
			" times in pkg/config non-test files, want exactly 1 (the MarshalJSON projection; the MarshalYAML duplicate is deleted, #17255)")
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Errorf("YAML redaction surface outside secret.go (#17255):\n  %s", strings.Join(violations, "\n  "))
	}
}
