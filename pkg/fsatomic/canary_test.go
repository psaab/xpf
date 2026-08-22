package fsatomic

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// allowedFunctions are the production functions permitted to keep a direct
// os.WriteFile call, keyed RECEIVER-AWARE by `<pkg-relpath>::[RecvType.]func`
// (#1916 D1). Every entry is a BestEffortKernelKnob (procfs/sysfs/bind-mount)
// where rename(2) is impossible by construction, so the fsatomic writers
// cannot be used.
//
// The key disambiguates methods from plain functions and from same-named
// functions in the same package directory: a future `pkg/daemon` `writeFile`
// on a DIFFERENT receiver type, or a plain func of the same name, will NOT
// inherit `daemon::realHostTunableFS.writeFile`'s exemption.
//
// Every non-pkg/daemon, non-pkg/api site below was verified (#1916 §2.C/§2.D)
// to be a procfs/sysfs/bind-mount knob — none is DurableState or
// AtomicGeneratedConfig. The pkg/daemon procfs writers were extracted into
// the three single-purpose helpers (setRethIPv6Knobs, setVLANSubAddrGenMode,
// setFibMultipathHashPolicy) so the giant applyConfigLocked / applyFRRConfig
// functions are NOT allowlisted — a future durable write added there is still
// caught.
var allowedFunctions = map[string]string{
	// pkg/daemon — sysctl / procfs knobs.
	"daemon::Daemon.applyKernelTuning":    "procfs sysctls (rp_filter etc.)",
	"daemon::enableForwarding":            "procfs sysctl forwarding bundle",
	"daemon::writeTransitForwardSysctls":  "procfs transit-forwarding knobs (#5275 arm gate)",
	"daemon::realHostTunableFS.writeFile": "sysfs governor/neigh knob writer",
	// pkg/daemon — DNS bind-mount fallback (rename onto a bind mount is
	// EXDEV/EBUSY; in-place write is the only option).
	"daemon::writeResolvConfBindMountFallback": "resolv.conf bind-mount in-place fallback",
	// pkg/daemon — procfs knobs extracted from the giant apply functions
	// (#1916 §2.D) so the big functions are never allowlisted.
	"daemon::setRethIPv6Knobs":          "procfs accept_dad / addr_gen_mode",
	"daemon::setVLANSubAddrGenMode":     "procfs addr_gen_mode (VLAN sub-iface)",
	"daemon::setFibMultipathHashPolicy": "procfs fib_multipath_hash_policy",
	// pkg/dataplane — RPS/RFS/XPS + accept_ra sysfs/procfs knobs.
	"dataplane::CompileResult.tuneInterfaceBuffers": "sysfs RPS/RFS/XPS knobs",
	"dataplane::ensureVLANSubInterface":             "procfs accept_ra knob",
	"dataplane::writeProxyResponderSysctl":          "procfs proxy_arp / proxy_ndp knob",
	// pkg/dataplane/userspace — socket-buffer sysctls.
	"dataplane/userspace::tuneSocketBuffers": "procfs socket-buffer sysctls",
	// pkg/networkd — slow-path rp_filter restore (procfs).
	"networkd::restoreSlowPathRPFilter": "procfs rp_filter knob",
}

// funcKey formats the receiver-aware allowlist key for a FuncDecl in the
// package at pkgRel. A method with receiver type T (or *T) is keyed
// "<pkgRel>::T.Method"; a plain function is keyed "<pkgRel>::Func".
func funcKey(pkgRel string, fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		recv := recvTypeName(fn.Recv.List[0].Type)
		if recv != "" {
			return pkgRel + "::" + recv + "." + fn.Name.Name
		}
	}
	return pkgRel + "::" + fn.Name.Name
}

// recvTypeName extracts the receiver type name, stripping a leading '*' for
// pointer receivers (so *T and T key identically).
func recvTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr: // generic receiver T[P]
		return recvTypeName(t.X)
	case *ast.IndexListExpr: // generic receiver T[P, Q]
		return recvTypeName(t.X)
	}
	return ""
}

// pkgRelKey turns a file path under ../ (the pkg/ root, relative to this
// test's directory pkg/fsatomic) into the package-relative key segment used
// in allowlist keys: e.g. "../daemon/x.go" -> "daemon",
// "../dataplane/userspace/p.go" -> "dataplane/userspace".
func pkgRelKey(file string) string {
	rel := filepath.ToSlash(file)
	rel = strings.TrimPrefix(rel, "../")
	return filepath.ToSlash(filepath.Dir(rel))
}

// TestNoDirectOsWriteFile is the #1916 writer-class repo-wide canary
// (rewrite of the #1894 package-allowlist canary). It walks EVERY
// production (non-test) .go file under pkg/ with go/ast — not grep, so
// comments may mention os.WriteFile freely and import aliases of the os
// package are still caught — and flags any direct os.WriteFile selector
// whose enclosing function is not in allowedFunctions.
//
// The repo-wide scan closes the "a new package silently escapes" hole of
// the old per-package allowlist; the receiver-aware key closes the
// "same package, same function name" hole (#1916 D1).
func TestNoDirectOsWriteFile(t *testing.T) {
	var violations []string
	scanned := 0

	root := ".." // pkg/ (this test lives in pkg/fsatomic)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		scanned++

		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}

		// Resolve the local identifier of the "os" import, including
		// aliases. A dot-import of os defeats the selector match — reject
		// it outright.
		osName := ""
		for _, imp := range f.Imports {
			ip, _ := strconv.Unquote(imp.Path.Value)
			if ip != "os" {
				continue
			}
			osName = "os"
			if imp.Name != nil {
				osName = imp.Name.Name
				if osName == "." {
					violations = append(violations,
						fmt.Sprintf("%s: dot-import of os defeats the WriteFile canary", path))
				}
			}
		}
		if osName == "" || osName == "_" || osName == "." {
			return nil
		}

		pkgRel := pkgRelKey(path)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if _, allowed := allowedFunctions[funcKey(pkgRel, fn)]; allowed {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "WriteFile" {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok || ident.Name != osName {
					return true
				}
				violations = append(violations, fmt.Sprintf(
					"%s: direct %s.WriteFile in %s — classify it (DurableState -> fsatomic.WriteFileDurable, AtomicGeneratedConfig -> fsatomic.WriteFileAtomic, BestEffortKernelKnob -> allowlist it in canary_test.go by its receiver-aware key with justification); see docs/engineering-style.md 'Persistence classes' (#1894/#1916)",
					fset.Position(call.Pos()), osName, funcKey(pkgRel, fn)))
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	// Self-test guard: a future glob/walk bug that scans nothing would
	// otherwise make this canary vacuously pass.
	t.Logf("scanned %d production .go files under pkg/", scanned)
	if scanned == 0 {
		t.Fatal("canary scanned 0 files — the repo walk is broken")
	}

	for _, v := range violations {
		t.Error(v)
	}
}

// TestFuncKeyReceiverAware pins the receiver-aware keyer (#1916 D1): plain
// functions, value receivers, and pointer receivers all key as documented.
func TestFuncKeyReceiverAware(t *testing.T) {
	const src = `package p
func Plain() {}
func (t T) Value() {}
func (t *T) Pointer() {}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]string{
		"Plain":   "pkg::Plain",
		"Value":   "pkg::T.Value",
		"Pointer": "pkg::T.Pointer",
	}
	seen := 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		got := funcKey("pkg", fn)
		if want[fn.Name.Name] != got {
			t.Errorf("funcKey(%s) = %q, want %q", fn.Name.Name, got, want[fn.Name.Name])
		}
		seen++
	}
	if seen != 3 {
		t.Fatalf("expected 3 func decls, saw %d", seen)
	}
}
