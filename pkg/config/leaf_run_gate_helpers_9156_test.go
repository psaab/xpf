package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func filepathGlob9156(pat string) ([]string, error) {
	return filepath.Glob(pat)
}

func readFile9156(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}

// gateCompileFlatSet9156 drives the FLAT-SET axis: it builds the container's
// prerequisite context from the braced text (which is the only form contextFor
// speaks) and then applies the statement(s) as `set` commands onto the SAME
// tree, so the run is the nested chain SetPath builds rather than a packed tail.
//
// `oneLine` selects the run: true puts both statements on one `set` line, false
// puts them on separate lines — the oracle.
// gateCompileFlatSet9156 applies the set lines onto base, the brace text of the
// fixture's context: empty for none, else the container's context as the
// braced arm renders it (#9792 fixtures included).
func gateCompileFlatSet9156(container []string, base, headStmt, tailStmt string, oneLine bool) (string, error) {
	var tree *ConfigTree
	if strings.TrimSpace(base) == "" {
		tree = &ConfigTree{}
	} else {
		p := NewParser(base)
		t, errs := p.Parse()
		if len(errs) > 0 {
			return "", fmt.Errorf("context parse: %v", errs)
		}
		tree = t
	}
	prefix := "set " + strings.Join(container, " ") + " "
	var cmds []string
	if oneLine {
		cmds = []string{prefix + headStmt + " " + tailStmt}
	} else {
		cmds = []string{prefix + headStmt, prefix + tailStmt}
	}
	for _, c := range cmds {
		path, err := ParseSetCommand(c)
		if err != nil {
			return "", err
		}
		if err := tree.SetPath(path); err != nil {
			return "", err
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		return "", err
	}
	return gateMarshal(cfg)
}

// ratchetLeafRunDiffers9156 is the ratchet DECISION, extracted so it can be
// driven directly.
//
// #9156: a mutation that made the gate bypass the register entirely — accept
// every difference as recorded — left the whole suite GREEN. The vacuity cell
// checked the register's SIZE, which says nothing about whether the register is
// CONSULTED. A ratchet that can be disarmed without a red is not a ratchet, and
// "make a surviving guard EXERCISABLE rather than excused" is the remedy: this
// is the smallest shape that lets a cell hand it a fabricated input and read the
// verdict back.
//
// Returns the differences NOT in the register (which must fail the gate) and the
// registered entries that no longer differ (which must also fail it, so the
// register cannot outlive the defect it describes).
func ratchetLeafRunDiffers9156(differed []string) (unrecorded, fixed []string) {
	seen := map[string]bool{}
	for _, d := range differed {
		seen[d] = true
		if !leafRunKnownDiffer9156[d] {
			unrecorded = append(unrecorded, d)
		}
	}
	for k := range leafRunKnownDiffer9156 {
		if !seen[k] {
			fixed = append(fixed, k)
		}
	}
	return unrecorded, fixed
}

// strictAdmitsLeafRun9156 reports whether the STRICT commit walk admits the
// one-line spelling of a leaf run (#9391).
//
// This is the operator-reachability discriminator. A row the strict gate
// REJECTS cannot be reached by committing: it needs a config file or an HA
// sync, and Store.compileTreeLenient logs a warning naming the leaf and saying
// the token would be dropped. A row the strict gate ADMITS is reachable by an
// operator typing one line, with no warning anywhere.
//
// It walks the same SchemaValidateWithDefinitions the commit path runs, on the
// braced rendering, so it is the gate's own verdict rather than a model of it.
// strictAdmitsLeafRun9156 reports whether the strict walk admits runText, the
// one-line spelling exactly as the braced arm compiled it.
func strictAdmitsLeafRun9156(runText string) bool {
	tree, errs := NewParser(runText).Parse()
	if len(errs) > 0 {
		return false
	}
	return SchemaValidateWithDefinitions(tree, tree, nil) == nil
}
