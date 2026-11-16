package fortestcensus

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// seamID names an exported *ForTest* seam: its package directory
// (slash-separated, relative to the scanned root), its receiver type ("" for
// a function) and its name.
type seamID struct{ dir, recv, name string }

func (s seamID) String() string {
	if s.recv == "" {
		return s.dir + "." + s.name
	}
	return s.dir + ".(" + s.recv + ")." + s.name
}

type seam struct {
	id   seamID
	file string // a defining file, relative to the root (build-tag variants may define it again)
	line int
}

var skipDirs = map[string]bool{".git": true, "vendor": true, "testdata": true, "node_modules": true, "target": true}

// isSeamName is the rule's subject: an EXPORTED name containing "ForTest"
// (ForTesting too). Exported, because that is the class the deadcode gate
// cannot see (an uncalled exported method on a live type reads reachable);
// unexported seams stay with that gate, which reports them.
func isSeamName(name string) bool { return ast.IsExported(name) && strings.Contains(name, "ForTest") }

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
		case *ast.ParenExpr:
			t = x.X
		case *ast.Ident:
			return x.Name
		default:
			return "?"
		}
	}
}

// scanSeams parses every non-test .go file under root, syntax only, and
// returns its exported *ForTest* funcs and methods. Nothing here counts
// references: whether a seam is called is not the question (#17342).
func scanSeams(root string) (map[seamID]*seam, error) {
	fset := token.NewFileSet()
	seams := map[seamID]*seam{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", p, perr)
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || !isSeamName(fd.Name.Name) {
				continue
			}
			id := seamID{dir: path.Dir(rel), recv: recvTypeName(fd.Recv), name: fd.Name.Name}
			if _, seen := seams[id]; !seen {
				seams[id] = &seam{id: id, file: rel, line: fset.Position(fd.Pos()).Line}
			}
		}
		return nil
	})
	return seams, err
}

// readAllow parses the seam list: <seam id>\t<reason> rows, # comments and
// blank lines. A malformed or duplicate row is a problem, not skipped.
func readAllow(p string) (map[string]string, []string, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, nil, err
	}
	rows := map[string]string{}
	var problems []string
	for i, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 2 || strings.TrimSpace(f[0]) == "" || strings.TrimSpace(f[1]) == "" {
			problems = append(problems, fmt.Sprintf("%s:%d: want <seam id>\\t<reason>, got %q", p, i+1, line))
			continue
		}
		if _, dup := rows[f[0]]; dup {
			problems = append(problems, fmt.Sprintf("%s:%d: duplicate row for %s", p, i+1, f[0]))
			continue
		}
		rows[f[0]] = f[1]
	}
	return rows, problems, nil
}

// check returns one problem per exported seam without a row and one per row
// naming no exported seam, sorted.
func check(seams map[seamID]*seam, rows map[string]string, allowName string) []string {
	var problems []string
	have := map[string]bool{}
	for id, s := range seams {
		have[id.String()] = true
		if _, ok := rows[id.String()]; !ok {
			problems = append(problems, fmt.Sprintf("%s:%d: exported seam %s has no row in %s: add one with the reason it is exported, or unexport it (the deadcode gate covers unexported seams)", s.file, s.line, id, allowName))
		}
	}
	for id := range rows {
		if !have[id] {
			problems = append(problems, fmt.Sprintf("%s: stale row %s: no exported *ForTest* func or method with that package, receiver and name exists", allowName, id))
		}
	}
	sort.Strings(problems)
	return problems
}
