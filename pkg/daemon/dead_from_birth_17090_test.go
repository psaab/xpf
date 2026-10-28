package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #17090: dead-from-birth declarations in pkg/daemon with live-sounding
// docs (staticcheck U1000). The ipsec ReinjectLease validator and the
// DHCP pending/applied generation fields were born uncalled: lease
// staleness is enforced by the Rust q0 writer
// (userspace-dp/src/slowpath_reinject_9506.rs) and by the live
// nfqueue.ReinjectLease minted in ipsec_capture_pipeline_9506.go, while
// the DHCP applied generation lives on the applier
// (Daemon.dhcpServer.AppliedGeneration). Reintroducing any of the
// symbols below recreates dead code whose docs claim a Go-side check
// that never runs.
//
// This is an AST guard over non-test daemon sources: it fails (RED)
// while any banned declaration is present and passes (GREEN) once it
// is deleted. The control is that the live counterparts must remain.

var deadFromBirth17090 = []string{
	"ipsecReinjectLease",
	"validateReinjectLease",
	"errIpsecGateClosed",
	"enqueueDHCPApply",
	"pendingApplyGeneration",
	"appliedGeneration",
}

// liveCounterparts17090 must stay: deleting the dead Go lease type must
// not remove the live nfqueue lease path, and deleting the dead Daemon
// generation fields must not remove the applier's AppliedGeneration.
var liveCounterparts17090 = []string{
	"enqueueDHCPApplyWithAuthorityState",
	"nextDHCPLeaseApplyAuthority",
	"authorityGeneration",
	"commitValidatedVerdict",
	"errIpsecPermitClosed",
	"errIpsecAlreadyTerminal",
}

func deadFromBirthViolations17090(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	banned := make(map[string]bool, len(deadFromBirth17090))
	for _, name := range deadFromBirth17090 {
		banned[name] = true
	}
	var violations []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(root, name)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		report := func(id *ast.Ident, kind string) {
			if banned[id.Name] {
				violations = append(violations,
					name+":"+fset.Position(id.Pos()).String()+" "+kind+" "+id.Name+" is dead-from-birth (#17090); delete it, do not wire it")
			}
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						report(s.Name, "type")
					case *ast.ValueSpec:
						for _, id := range s.Names {
							report(id, "var/const")
						}
					}
				}
			case *ast.FuncDecl:
				report(d.Name, "func")
			}
		}
		// Struct fields (e.g. dhcpLeaseSyncState.pendingApplyGeneration).
		ast.Inspect(file, func(n ast.Node) bool {
			field, ok := n.(*ast.Field)
			if !ok {
				return true
			}
			for _, id := range field.Names {
				report(id, "field")
			}
			return true
		})
	}
	return violations
}

func TestDeadFromBirthDeclarationsAbsent17090(t *testing.T) {
	t.Parallel()
	if violations := deadFromBirthViolations17090(t, "."); len(violations) > 0 {
		t.Fatalf("dead-from-birth declarations still present (#17090):\n%s",
			strings.Join(violations, "\n"))
	}
	// Positive control: the live counterparts must still be declared in
	// the same files, proving the guard did not pass by parsing nothing.
	srcSupervisor, err := os.ReadFile("ipsec_reinject_supervisor.go")
	if err != nil {
		t.Fatalf("read supervisor: %v", err)
	}
	srcDHCP, err := os.ReadFile("daemon_dhcp_lease_sync.go")
	if err != nil {
		t.Fatalf("read dhcp lease sync: %v", err)
	}
	combined := string(srcSupervisor) + "\n" + string(srcDHCP)
	for _, live := range liveCounterparts17090 {
		if !strings.Contains(combined, live) {
			t.Fatalf("live counterpart %q missing after #17090 deletion; guard control failed", live)
		}
	}
	// The live nfqueue lease type is outside pkg/daemon and must remain
	// the sole Go ReinjectLease.
	if _, err := os.Stat(filepath.Join("..", "nfqueue", "pipeline.go")); err != nil {
		t.Fatalf("live nfqueue lease file missing: %v", err)
	}
}

func TestDeadFromBirthDeclarationsAbsent17090SelfTest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `package daemon

type ipsecReinjectLease struct{ PermitEpoch uint64 }

type state struct {
	pendingApplyGeneration uint64
	appliedGeneration      uint64
}

var errIpsecGateClosed = errors.New("closed")

func (d *Daemon) enqueueDHCPApply() {}
func (s *ipsecSupervisor) validateReinjectLease(lease ipsecReinjectLease) error { return nil }
var _ = state{}
`
	if err := os.WriteFile(filepath.Join(dir, "synthetic.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	violations := deadFromBirthViolations17090(t, dir)
	if len(violations) != len(deadFromBirth17090) {
		t.Fatalf("self-test: got %d violations, want %d:\n%s",
			len(violations), len(deadFromBirth17090), strings.Join(violations, "\n"))
	}
	clean := `package daemon

type state struct {
	authorityGeneration uint64
}

func (d *Daemon) enqueueDHCPApplyWithAuthorityState() uint64 { return 1 }
`
	if err := os.WriteFile(filepath.Join(dir, "synthetic.go"), []byte(clean), 0o644); err != nil {
		t.Fatal(err)
	}
	if violations := deadFromBirthViolations17090(t, dir); len(violations) != 0 {
		t.Fatalf("self-test clean source flagged: %v", violations)
	}
}
