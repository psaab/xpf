package denyaudit

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

// #9042 acceptance: no unbounded per-request Warn remains on an authorization
// path, and every known denial site still routes through this package.
//
// SOURCE-LEVEL BY NECESSITY. Driving all seven behaviorally needs a live
// fabric listener with a real PSK, a peer UID that resolves to an empty-Class
// principal, cross-site HTTP, REST authorization, and REST credential failures
// -- and the property is about the SHAPE of the call, which a behavioural test
// cannot distinguish from a lucky quiet log. So the wiring is bound instead.
//
// RED means either a site stopped routing through denyaudit (the flood is
// back) or a new one appeared unguarded.
func TestEveryDenialSiteIsBounded9042(t *testing.T) {
	sites := []struct{ file, fn string }{
		{"../grpcapi/authz.go", "denyRPC"},
		{"../grpcapi/fabric_auth.go", "checkFabricAuthRequest"},
		{"../grpcapi/server.go", "fabricAllowlistUnaryInterceptor"},
		{"../grpcapi/server.go", "fabricAllowlistStreamInterceptor"},
		{"../api/crosssite.go", "mutationCrossSiteGuard"},
		{"../api/authz.go", "logRESTLoginDenial"},
		{"../api/auth.go", "logRESTAPIAuthFailure"},
	}
	for _, s := range sites {
		src, err := os.ReadFile(s.file)
		if err != nil {
			t.Errorf("#9042: cannot read %s: %v — this guard is keyed to that path, so a "+
				"move must bring it along rather than silently disarm it", s.file, err)
			continue
		}
		body, ok := funcBody9042(string(src), s.fn)
		if !ok {
			t.Errorf("#9042: %s not found in %s — keyed by name; a rename must update this "+
				"guard rather than disarm it", s.fn, s.file)
			continue
		}
		if !strings.Contains(body, "denyaudit.Note(") {
			t.Errorf("#9042: %s in %s does not route its denial through denyaudit.Note. "+
				"An unbounded per-request Warn on an authorization path ships to remote "+
				"syslog at a rate the caller controls, and pushes xpfd's other lines past "+
				"journald's cap.", s.fn, s.file)
		}
	}
}

// The seven are the WHOLE set. A new unguarded site is the same defect
// arriving somewhere new, and a site quietly dropped is the fix being undone.
func TestDenialSiteCountIsPinned9042(t *testing.T) {
	var found []string
	for _, dir := range []string{"../grpcapi", "../api"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("#9042: cannot read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			n := strings.Count(string(b), "denyaudit.Note(")
			for i := 0; i < n; i++ {
				found = append(found, filepath.Join(dir, e.Name()))
			}
		}
	}
	sort.Strings(found)
	const want = 7
	if len(found) != want {
		t.Errorf("#9042: %d denyaudit.Note call sites, want %d:\n  %s\n\n"+
			"GREW: a new denial site was added — confirm it is on a per-request path and "+
			"that its key is not attacker-supplied. SHRANK: a site stopped being bounded, "+
			"which restores the flood at that surface.",
			len(found), want, strings.Join(found, "\n  "))
	}
}

// funcBody9042 returns the source text of fn's BODY.
//
// Parsed rather than brace-counted: `interface{}` in a signature made a
// hand-rolled counter open and close its depth inside the PARAMETER LIST, so it
// returned the signature and reported that both fabric interceptors -- which do
// route through denyaudit -- did not. A guard that reads the wrong bytes fails
// in the direction that looks like a real finding.
func funcBody9042(src, fn string) (string, bool) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		return "", false
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		return src[fset.Position(fd.Body.Pos()).Offset:fset.Position(fd.Body.End()).Offset], true
	}
	return "", false
}
