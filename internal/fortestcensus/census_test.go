package fortestcensus

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// hookID names a hook: its package directory (slash-separated, relative to
// the module root), its receiver type ("" for a function) and its name.
type hookID struct{ dir, recv, name string }

func (h hookID) String() string {
	if h.recv == "" {
		return h.dir + "." + h.name
	}
	return h.dir + ".(" + h.recv + ")." + h.name
}

type hook struct {
	id   hookID
	file string // defining file, relative to the module root
	pkg  string // package clause of the defining file
	refs int
}

type allowRow struct{ id, file, reason string }

type censusResult struct {
	hooks    map[hookID]*hook
	dead     []*hook
	problems []string
}

var skipDirs = map[string]bool{".git": true, "vendor": true, "testdata": true, "node_modules": true, "target": true}

// isHookName: the census's subject, a name containing "ForTest" (ForTesting too).
func isHookName(name string) bool { return strings.Contains(name, "ForTest") }

type parsedFile struct {
	rel     string // relative path
	dir     string // relative package directory
	pkg     string
	file    *ast.File
	imports map[string]string // local name -> import path
}

func modulePath(root string) (string, error) {
	f, err := os.Open(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) == 2 && fields[0] == "module" {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("%s/go.mod declares no module", root)
}

func recvTypeName(fl *ast.FieldList) string {
	if fl == nil || len(fl.List) == 0 {
		return ""
	}
	t := fl.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
		case *ast.IndexExpr:
			t = x.X
		case *ast.IndexListExpr:
			t = x.X
		case *ast.Ident:
			return x.Name
		default:
			return "?"
		}
	}
}

// runCensus parses every .go file under root and attributes each reference.
func runCensus(root string, allow []allowRow) (*censusResult, error) {
	mod, err := modulePath(root)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var files []*parsedFile
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", p, perr)
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		pf := &parsedFile{rel: rel, dir: path.Dir(rel), pkg: f.Name.Name, file: f, imports: map[string]string{}}
		for _, im := range f.Imports {
			ip, _ := strconv.Unquote(im.Path.Value)
			local := path.Base(ip)
			if im.Name != nil {
				local = im.Name.Name
			}
			pf.imports[local] = ip
		}
		files = append(files, pf)
		return nil
	})
	if err != nil {
		return nil, err
	}
	res := &censusResult{hooks: map[hookID]*hook{}}
	byName := map[string][]*hook{}
	declNames := map[*ast.Ident]bool{}
	for _, pf := range files {
		if strings.HasSuffix(pf.rel, "_test.go") {
			continue
		}
		for _, decl := range pf.file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || !isHookName(fd.Name.Name) {
				continue
			}
			id := hookID{dir: pf.dir, recv: recvTypeName(fd.Recv), name: fd.Name.Name}
			if prev, dup := res.hooks[id]; dup {
				res.problems = append(res.problems, fmt.Sprintf("%s is defined twice (%s, %s); build-tagged twins need one row each, which this census cannot key", id, prev.file, pf.rel))
				continue
			}
			h := &hook{id: id, file: pf.rel, pkg: pf.pkg}
			res.hooks[id] = h
			byName[id.name] = append(byName[id.name], h)
			declNames[fd.Name] = true
		}
	}
	if len(res.hooks) == 0 {
		return nil, fmt.Errorf("no *ForTest* hooks under %s; nothing to vouch for", root)
	}
	dirOf := func(importPath string) (string, bool) {
		if importPath == mod {
			return ".", true
		}
		if strings.HasPrefix(importPath, mod+"/") {
			return strings.TrimPrefix(importPath, mod+"/"), true
		}
		return "", false
	}
	// Types first: a selector or identifier that go/types resolves to a hook
	// is attributed exactly. Everything module-internal is type-checked from
	// the ASTs parsed above; only third-party imports are stubbed, so a
	// receiver of a module type resolves even through a field of another
	// package's type (d.cluster.X()).
	resolved := resolveWithTypes(fset, files, mod, dirOf)
	for _, pf := range files {
		inScope := map[string]bool{pf.dir: true}
		for _, ip := range pf.imports {
			if d, ok := dirOf(ip); ok {
				inScope[d] = true
			}
		}
		selectorSel := map[*ast.Ident]bool{}
		ast.Inspect(pf.file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !isHookName(sel.Sel.Name) {
				return true
			}
			selectorSel[sel.Sel] = true
			if id, ok := resolved[sel.Sel]; ok {
				if h := res.hooks[id]; h != nil {
					h.refs++
				}
				return true
			}
			var cands []*hook
			if x, isIdent := sel.X.(*ast.Ident); isIdent && pf.imports[x.Name] != "" {
				// pkg.Hook: a function in the imported package.
				if d, ok := dirOf(pf.imports[x.Name]); ok {
					if h := res.hooks[hookID{dir: d, name: sel.Sel.Name}]; h != nil {
						cands = append(cands, h)
					}
				}
			} else {
				// x.Hook that types could not resolve (a call through an
				// interface, or a third-party-typed chain): the one method
				// hook of that name, else those in this package or its imports.
				var all []*hook
				for _, h := range byName[sel.Sel.Name] {
					if h.id.recv != "" {
						all = append(all, h)
					}
				}
				if len(all) == 1 {
					cands = all
				} else {
					for _, h := range all {
						if inScope[h.id.dir] {
							cands = append(cands, h)
						}
					}
				}
			}
			switch len(cands) {
			case 0:
			case 1:
				cands[0].refs++
			default:
				var ids []string
				for _, h := range cands {
					ids = append(ids, h.id.String())
				}
				sort.Strings(ids)
				res.problems = append(res.problems, fmt.Sprintf("%s: %s is ambiguous between %s; the census cannot attribute it", fset.Position(sel.Pos()), sel.Sel.Name, strings.Join(ids, ", ")))
			}
			return true
		})
		ast.Inspect(pf.file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || !isHookName(id.Name) || declNames[id] || selectorSel[id] {
				return true
			}
			if rid, ok := resolved[id]; ok {
				if h := res.hooks[rid]; h != nil {
					h.refs++
				}
				return true
			}
			// A bare Hook: a function of this very package.
			if h := res.hooks[hookID{dir: pf.dir, name: id.Name}]; h != nil && h.pkg == pf.pkg {
				h.refs++
			}
			return true
		})
	}
	allowed := map[string]allowRow{}
	for _, row := range allow {
		allowed[row.id] = row
	}
	var ids []string
	for id := range res.hooks {
		ids = append(ids, id.String())
	}
	sort.Strings(ids)
	byString := map[string]*hook{}
	for _, h := range res.hooks {
		byString[h.id.String()] = h
	}
	for _, s := range ids {
		h := byString[s]
		if h.refs > 0 {
			continue
		}
		res.dead = append(res.dead, h)
		if _, ok := allowed[s]; !ok {
			res.problems = append(res.problems, fmt.Sprintf("%s: %s has no caller (comments and strings do not count). Delete it, call it, or list it in the baseline with a reason", h.file, s))
		}
	}
	var rows []string
	for id := range allowed {
		rows = append(rows, id)
	}
	sort.Strings(rows)
	for _, s := range rows {
		row := allowed[s]
		h := byString[s]
		switch {
		case h == nil:
			res.problems = append(res.problems, fmt.Sprintf("baseline row %s (%s) is stale: the hook is gone; delete the row", s, row.file))
		case h.refs > 0:
			res.problems = append(res.problems, fmt.Sprintf("baseline row %s (%s) is stale: the hook now has a caller; delete the row", s, row.file))
		case h.file != row.file:
			res.problems = append(res.problems, fmt.Sprintf("baseline row %s names %s, but the hook is defined in %s; a moved hook needs its row re-examined", s, row.file, h.file))
		}
	}
	return res, nil
}

// readAllow parses the baseline: <hook id>\t<file>\t<reason>, # comments.
func readAllow(p string) ([]allowRow, []string, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, nil, err
	}
	var rows []allowRow
	var problems []string
	for i, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 || strings.TrimSpace(f[0]) == "" || strings.TrimSpace(f[1]) == "" || strings.TrimSpace(f[2]) == "" {
			problems = append(problems, fmt.Sprintf("%s:%d: want <hook id>\\t<file>\\t<reason>, got %q", p, i+1, line))
			continue
		}
		rows = append(rows, allowRow{id: f[0], file: f[1], reason: f[2]})
	}
	return rows, problems, nil
}

// modImporter type-checks module-internal packages from already-parsed
// non-test files, imports the standard library from the toolchain's export
// data (so atomic.Pointer[T].Load() and friends resolve), and stubs every
// third-party import (an empty package).
type modImporter struct {
	fset  *token.FileSet
	dirOf func(string) (string, bool)
	files map[string][]*ast.File // package dir -> non-test files of its main package clause
	pkgs  map[string]*types.Package
	std   types.Importer
}

func (m *modImporter) Import(importPath string) (*types.Package, error) {
	if p := m.pkgs[importPath]; p != nil {
		return p, nil
	}
	if d, ok := m.dirOf(importPath); ok && len(m.files[d]) > 0 {
		// Mark the path first: a cycle (impossible in valid Go) then gets a
		// stub instead of infinite recursion.
		m.pkgs[importPath] = stubPackage(importPath)
		conf := types.Config{Importer: m, Error: func(error) {}}
		p, _ := conf.Check(importPath, m.fset, m.files[d], nil)
		if p != nil {
			m.pkgs[importPath] = p
		}
		return m.pkgs[importPath], nil
	}
	if first, _, _ := strings.Cut(importPath, "/"); !strings.Contains(first, ".") && m.std != nil {
		if p, err := m.std.Import(importPath); err == nil && p != nil {
			m.pkgs[importPath] = p
			return p, nil
		}
	}
	p := stubPackage(importPath)
	m.pkgs[importPath] = p
	return p, nil
}

func stubPackage(importPath string) *types.Package {
	name := path.Base(importPath)
	if i := strings.IndexAny(name, ".-"); i > 0 {
		name = name[:i]
	}
	p := types.NewPackage(importPath, name)
	p.MarkComplete()
	return p
}

// resolveWithTypes type-checks every package group (its non-test files plus
// the test files of the same package clause, and each external _test
// package) and returns the hook each resolvable selector or identifier names.
func resolveWithTypes(fset *token.FileSet, files []*parsedFile, mod string, dirOf func(string) (string, bool)) map[*ast.Ident]hookID {
	mainClause := map[string]string{} // dir -> package clause of its non-test files
	imp := &modImporter{fset: fset, dirOf: dirOf, files: map[string][]*ast.File{}, pkgs: map[string]*types.Package{}, std: importer.ForCompiler(fset, "gc", nil)}
	for _, pf := range files {
		if !strings.HasSuffix(pf.rel, "_test.go") {
			if _, seen := mainClause[pf.dir]; !seen {
				mainClause[pf.dir] = pf.pkg
			}
			if pf.pkg == mainClause[pf.dir] {
				imp.files[pf.dir] = append(imp.files[pf.dir], pf.file)
			}
		}
	}
	type groupKey struct{ dir, clause string }
	groups := map[groupKey][]*ast.File{}
	var order []groupKey
	for _, pf := range files {
		k := groupKey{pf.dir, pf.pkg}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], pf.file)
	}
	out := map[*ast.Ident]hookID{}
	for _, k := range order {
		importPath := mod
		if k.dir != "." {
			importPath = mod + "/" + k.dir
		}
		if k.clause != mainClause[k.dir] {
			importPath += "_test"
		}
		info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
		conf := types.Config{Importer: imp, Error: func(error) {}}
		_, _ = conf.Check(importPath, fset, groups[k], info)
		for sel, s := range info.Selections {
			if id, ok := hookOf(s.Obj(), dirOf); ok {
				out[sel.Sel] = id
			}
		}
		for ident, obj := range info.Uses {
			if _, done := out[ident]; done {
				continue
			}
			if id, ok := hookOf(obj, dirOf); ok {
				out[ident] = id
			}
		}
	}
	return out
}

// hookOf maps a resolved function or concrete method to its hook id. A method
// of an interface is not a hook definition, so it does not resolve.
func hookOf(obj types.Object, dirOf func(string) (string, bool)) (hookID, bool) {
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil || !isHookName(fn.Name()) {
		return hookID{}, false
	}
	d, ok := dirOf(strings.TrimSuffix(fn.Pkg().Path(), "_test"))
	if !ok {
		return hookID{}, false
	}
	recv := ""
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		t := sig.Recv().Type()
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
		}
		named, ok := t.(*types.Named)
		if !ok {
			return hookID{}, false
		}
		if _, iface := named.Underlying().(*types.Interface); iface {
			return hookID{}, false // a call through an interface names no concrete hook
		}
		recv = named.Obj().Name()
	}
	return hookID{dir: d, recv: recv, name: fn.Name()}, true
}
