package userspace

// Census guard (#18696): no loop in pkg/ deletes from a map while it walks that same
// map, except walkDeleteBPFKeys, which reads the next key first. A loop that walks and
// deletes some other way must go through walkDeleteBPFKeys. A walk that only COLLECTS
// keys and deletes after the loop is fine and is not flagged.
//
// WHAT IT SEES. A walk is:
//   - a for loop that calls NextKey* (any name with that prefix, e.g. NextKeyBytes)
//     or an iterator's Next in its Init, Cond, Post or Body; or
//   - a range over a Keys/All/Values/Iterate call (a range-over-func iterator).
//
// The walked map is the receiver of that call. For an iterator it is the receiver
// of the Iterate() that produced the iterator, found in the loop's Init or in an
// assignment earlier in the same function. A delete is a Delete/BatchDelete call in
// the loop body whose receiver is the walked map. A delete through a DIRECT call to
// a same-package function counts too, when that function deletes through one of
// its parameters and the loop passes the walked map in that position. A delete on
// a different map is not this bug and is not flagged.
//
// WHAT IT CANNOT SEE (a syntactic scan, no type information):
//   - a delete reached through a method, a closure, a function value, an interface
//     or another package;
//   - a map reached under another name (an alias, a struct field read twice);
//   - an iterator whose origin is not a visible Iterate() call: that walk matches
//     ANY delete in its body, so it fails closed.
//
// The Rust helper has no such guard; its census (#18696) was by hand, see
// pkg/dataplane/README.md.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// unknownWalk stands for an iterator whose map the scan cannot name: such a walk
// matches every delete in its body.
const unknownWalk = "?"

// walkMarkers selects the files worth parsing for walks. It is keyed on the WALK,
// not on the delete, because the delete may be in another file (a helper) or be a
// BatchDelete. A file with none of these cannot contain a walk loop.
var walkMarkers = []string{"NextKey", ".Next(", "Iterate()", ".Keys()", ".All()", ".Values()"}

func mayWalkAMap(src string) bool {
	for _, m := range walkMarkers {
		if strings.Contains(src, m) {
			return true
		}
	}
	return false
}

// mayDeleteFromAMap selects the files worth parsing for delete helpers. It matches
// Delete( and BatchDelete( alike.
func mayDeleteFromAMap(src string) bool { return strings.Contains(src, "Delete(") }

func isNextKeyName(name string) bool { return strings.HasPrefix(name, "NextKey") }

func isDeleteName(name string) bool { return name == "Delete" || name == "BatchDelete" }

// deleteHelpers maps each plain function in files to the positions of the
// parameters it deletes through (a Delete/BatchDelete call whose receiver is that
// parameter).
func deleteHelpers(files []*ast.File) map[string]map[int]bool {
	helpers := map[string]map[int]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			index := map[string]int{}
			i := 0
			for _, field := range fn.Type.Params.List {
				for _, name := range field.Names {
					index[name.Name] = i
					i++
				}
				if len(field.Names) == 0 {
					i++
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !isDeleteName(sel.Sel.Name) {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok {
					if pos, ok := index[id.Name]; ok {
						if helpers[fn.Name.Name] == nil {
							helpers[fn.Name.Name] = map[int]bool{}
						}
						helpers[fn.Name.Name][pos] = true
					}
				}
				return true
			})
		}
	}
	return helpers
}

// iteratorSource names the map an iterator variable came from: the receiver of
// `name := X.Iterate()` / `name = X.Iterate()` in the loop's Init, or else the last
// such assignment in fn before the loop.
func iteratorSource(fn *ast.FuncDecl, loop *ast.ForStmt, name string) string {
	source := unknownWalk
	consider := func(n ast.Node) {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || id.Name != name {
			return
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Iterate" {
			source = types.ExprString(sel.X)
		}
	}
	if loop.Init != nil {
		consider(loop.Init)
		if source != unknownWalk {
			return source
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if n != nil && n.Pos() < loop.Pos() {
			consider(n)
		}
		return true
	})
	return source
}

// walkedMaps returns the maps a loop walks (receiver expressions), and its body.
func walkedMaps(fn *ast.FuncDecl, n ast.Node) (map[string]bool, *ast.BlockStmt) {
	walked := map[string]bool{}
	switch loop := n.(type) {
	case *ast.ForStmt:
		for _, part := range []ast.Node{loop.Init, loop.Cond, loop.Post, loop.Body} {
			if part == nil {
				continue
			}
			ast.Inspect(part, func(m ast.Node) bool {
				call, ok := m.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch {
				case isNextKeyName(sel.Sel.Name):
					walked[types.ExprString(sel.X)] = true
				case sel.Sel.Name == "Next":
					if id, ok := sel.X.(*ast.Ident); ok {
						walked[iteratorSource(fn, loop, id.Name)] = true
					} else if inner, ok := sel.X.(*ast.CallExpr); ok {
						// m.Iterate().Next(...) in place.
						if s, ok := inner.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Iterate" {
							walked[types.ExprString(s.X)] = true
						}
					}
				}
				return true
			})
		}
		return walked, loop.Body
	case *ast.RangeStmt:
		if call, ok := loop.X.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "Keys", "All", "Values", "Iterate":
					walked[types.ExprString(sel.X)] = true
				}
			}
		}
		return walked, loop.Body
	}
	return nil, nil
}

func matchesWalk(walked map[string]bool, receiver string) bool {
	return walked[unknownWalk] || walked[receiver]
}

// deleteDuringWalk reports "position funcName" for each loop in file that deletes
// from the map it is walking, directly or through a helper in helpers.
func deleteDuringWalk(fset *token.FileSet, file *ast.File, helpers map[string]map[int]bool) []string {
	var hits []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			walked, body := walkedMaps(fn, n)
			if len(walked) == 0 || body == nil {
				return true
			}
			deletes := false
			ast.Inspect(body, func(m ast.Node) bool {
				call, ok := m.(*ast.CallExpr)
				if !ok || deletes {
					return !deletes
				}
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					if isDeleteName(fun.Sel.Name) && matchesWalk(walked, types.ExprString(fun.X)) {
						deletes = true
					}
				case *ast.Ident:
					for pos := range helpers[fun.Name] {
						if pos < len(call.Args) && matchesWalk(walked, types.ExprString(call.Args[pos])) {
							deletes = true
						}
					}
				}
				return !deletes
			})
			if deletes {
				hits = append(hits, fset.Position(n.Pos()).String()+" "+fn.Name.Name)
			}
			return true
		})
	}
	return hits
}

// censusControl is one function per shape. A name starting "flag" must be reported
// exactly once; "pass" must not be.
const censusControl = `package p
type bpfMap interface {
	NextKey(a, b interface{}) error
	NextKeyBytes(a interface{}) ([]byte, error)
	Delete(a interface{}) error
	BatchDelete(a interface{}, o interface{}) (int, error)
	Iterate() iter
	Keys() func(func([]byte) bool)
}
type iter interface{ Next(k, v interface{}) bool }

func flagNextKeyInBody(m bpfMap) {
	key, next := make([]byte, 4), make([]byte, 4)
	for {
		if err := m.NextKey(key, next); err != nil { break }
		copy(key, next)
		_ = m.Delete(key)
	}
}
func flagNextKeyInCondition(m bpfMap) {
	for k := make([]byte, 4); m.NextKey(k, k) == nil; {
		_ = m.Delete(k)
	}
}
func flagNextKeyInInitAndPost(m bpfMap) {
	k := make([]byte, 4)
	for err := m.NextKey(nil, k); err == nil; err = m.NextKey(k, k) {
		_ = m.Delete(k)
	}
}
func flagNextKeyBytes(m bpfMap) {
	for k, err := m.NextKeyBytes(nil); err == nil; k, err = m.NextKeyBytes(k) {
		_ = m.Delete(k)
	}
}
func flagBatchDelete(m bpfMap) {
	k := make([]byte, 4)
	for m.NextKey(k, k) == nil {
		_, _ = m.BatchDelete([][]byte{k}, nil)
	}
}
func flagIteratorInInit(m bpfMap) {
	var k, v []byte
	for it := m.Iterate(); it.Next(&k, &v); {
		_ = m.Delete(k)
	}
}
func flagIteratorBeforeLoop(m bpfMap) {
	var k, v []byte
	it := m.Iterate()
	for it.Next(&k, &v) {
		_ = m.Delete(k)
	}
}
func flagRangeOverKeys(m bpfMap) {
	for k := range m.Keys() {
		_ = m.Delete(k)
	}
}
func dropRow(target bpfMap, k []byte) { _ = target.Delete(k) }
func flagDeleteThroughHelper(m bpfMap) {
	k := make([]byte, 4)
	for m.NextKey(k, k) == nil {
		dropRow(m, k)
	}
}
func passCollectThenDelete(m bpfMap) {
	var k, v []byte
	var stale [][]byte
	for it := m.Iterate(); it.Next(&k, &v); {
		stale = append(stale, k)
	}
	for _, s := range stale {
		_ = m.Delete(s)
	}
}
func passWalkADeleteB(a, b bpfMap) {
	k := make([]byte, 4)
	for err := a.NextKey(nil, k); err == nil; err = a.NextKey(k, k) {
		_ = b.Delete(k)
	}
}
func passIteratorOfADeleteB(a, b bpfMap) {
	var k, v []byte
	it := a.Iterate()
	for it.Next(&k, &v) {
		_ = b.Delete(k)
	}
}
func passHelperOnOtherMap(a, b bpfMap) {
	k := make([]byte, 4)
	for a.NextKey(k, k) == nil {
		dropRow(b, k)
	}
}
func passNextKeyBytesReadOnly(m bpfMap) (n int) {
	for k, err := m.NextKeyBytes(nil); err == nil; k, err = m.NextKeyBytes(k) {
		n++
	}
	return n
}
`

func TestNoDeleteDuringBPFMapWalk18696(t *testing.T) {
	// Controls: every flag* shape is reported exactly once, and no pass* shape is.
	fset := token.NewFileSet()
	control, err := parser.ParseFile(fset, "control.go", censusControl, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, hit := range deleteDuringWalk(fset, control, deleteHelpers([]*ast.File{control})) {
		got[hit[strings.LastIndex(hit, " ")+1:]]++
	}
	var shapes []string
	for _, decl := range control.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			shapes = append(shapes, fn.Name.Name)
		}
	}
	sort.Strings(shapes)
	for _, shape := range shapes {
		switch {
		case strings.HasPrefix(shape, "flag") && got[shape] != 1:
			t.Errorf("detector control: %s flagged %d times, want 1", shape, got[shape])
		case strings.HasPrefix(shape, "pass") && got[shape] != 0:
			t.Errorf("detector control: %s flagged %d times, want 0 (not this bug)", shape, got[shape])
		}
	}
	// The file selection must not skip a BatchDelete-only file or a helper file.
	if !mayWalkAMap("for m.NextKey(k, k) == nil { m.BatchDelete(ks, nil) }") ||
		!mayDeleteFromAMap("func drop(m M) { m.BatchDelete(ks, nil) }") ||
		mayWalkAMap("func f() { x := 1; _ = x }") {
		t.Errorf("file selection: a BatchDelete-only walk or helper file would be skipped")
	}
	if t.Failed() {
		t.FailNow()
	}

	_, here, _, _ := runtime.Caller(0)
	pkgRoot := filepath.Join(filepath.Dir(here), "..", "..")
	byDir := map[string][]*ast.File{}
	walkers := map[*ast.File]bool{}
	err = filepath.WalkDir(pkgRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		walks, deletes := mayWalkAMap(string(src)), mayDeleteFromAMap(string(src))
		if !walks && !deletes {
			return nil
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		byDir[filepath.Dir(path)] = append(byDir[filepath.Dir(path)], file)
		if walks {
			walkers[file] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(walkers) == 0 {
		t.Fatal("census selected no files: the pkg/ root is wrong")
	}
	var offenders []string
	for _, files := range byDir {
		helpers := deleteHelpers(files)
		for _, file := range files {
			if !walkers[file] {
				continue
			}
			for _, hit := range deleteDuringWalk(fset, file, helpers) {
				if !strings.HasSuffix(hit, " walkDeleteBPFKeys") {
					offenders = append(offenders, hit)
				}
			}
		}
	}
	if len(offenders) != 0 {
		sort.Strings(offenders)
		t.Fatalf("loops delete from a map while walking it; use walkDeleteBPFKeys (#18696):\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
