package testguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// netnsSwitchCalls are the calls that move the calling thread into another
// network namespace, by import path.
var netnsSwitchCalls = map[string]map[string]bool{
	"github.com/vishvananda/netns": {"New": true, "NewNamed": true, "Set": true, "Setns": true},
	"golang.org/x/sys/unix":        {"Setns": true, "Unshare": true},
	"syscall":                      {"Unshare": true},
}

// CheckNetnsThreadDiscipline is the static half of #19088. Run (the runtime
// half) catches a thread that WAS left in a foreign namespace by a path the
// package's tests took; this catches the paths they did not take: the error
// arms that only run when a restore or an open fails. It reports, for every
// _test.go file in dir:
//   - a file that switches a thread's network namespace and also calls
//     runtime.LockOSThread or runtime.UnlockOSThread directly. Such a file
//     must lock through LockThreadNetns and release through Release (or use
//     InNetns, EnterNewNetns, EnterNetns), which restore before they unlock
//     and keep the thread locked when they cannot;
//   - any "/proc/self/ns/" path, which names the thread-group leader's
//     namespace, not the calling thread's (use /proc/thread-self/ns/).
//
// Calls that switch while a helper already holds the thread (an inner
// netns.Set under EnterNewNetns) are allowed: the helper's Release restores
// whatever the inner switch left.
func CheckNetnsThreadDiscipline(dir string) error {
	paths, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("no _test.go files under %s", dir)
	}
	sort.Strings(paths)
	var findings []string
	for _, path := range paths {
		got, err := netnsThreadFindings(path)
		if err != nil {
			return err
		}
		findings = append(findings, got...)
	}
	if len(findings) > 0 {
		return fmt.Errorf("#19088 netns thread discipline:\n  %s", strings.Join(findings, "\n  "))
	}
	return nil
}

func netnsThreadFindings(path string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// Local name -> import path, for the packages the rules name.
	imports := map[string]string{}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		if importPath != "runtime" && netnsSwitchCalls[importPath] == nil {
			continue
		}
		name := importPath[strings.LastIndex(importPath, "/")+1:]
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "_" || name == "." {
			continue
		}
		imports[name] = importPath
	}
	var switches []token.Pos
	var rawLocks []string
	var findings []string
	ast.Inspect(file, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.BasicLit:
			if node.Kind == token.STRING && strings.Contains(node.Value, "/proc/self/ns/") {
				findings = append(findings, fmt.Sprintf("%s: %s names the thread-group leader's namespace; use /proc/thread-self/ns/",
					fset.Position(node.Pos()), node.Value))
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			importPath, ok := imports[pkg.Name]
			if !ok {
				return true
			}
			if importPath == "runtime" {
				if sel.Sel.Name == "LockOSThread" || sel.Sel.Name == "UnlockOSThread" {
					rawLocks = append(rawLocks, fmt.Sprintf("%s: runtime.%s", fset.Position(node.Pos()), sel.Sel.Name))
				}
				return true
			}
			if netnsSwitchCalls[importPath][sel.Sel.Name] {
				switches = append(switches, node.Pos())
			}
		}
		return true
	})
	if len(switches) > 0 {
		for _, lock := range rawLocks {
			findings = append(findings, fmt.Sprintf("%s in a file that switches netns (%s); lock with testguard.LockThreadNetns and release with Release",
				lock, fset.Position(switches[0])))
		}
	}
	return findings, nil
}
