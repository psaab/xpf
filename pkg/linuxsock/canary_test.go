package linuxsock

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
// unix.Socket(...) CALL, keyed RECEIVER-AWARE by `<pkg-relpath>::[RecvType.]func`
// (mirrors the #1916 fsatomic canary key). Each entry must OR SOCK_CLOEXEC into
// the type argument itself and carry its own fail-on-revert test.
//
// linuxsock.Socket is the SSOT factory: it is exempt because it IS the wrapper
// that forces SOCK_CLOEXEC.
//
// pkg/vrrp::openAfPacketReceiver predates this package (#2476). It already ORs
// SOCK_CLOEXEC into the type at its call site and is pinned by
// pkg/vrrp/afpacket_cloexec_test.go, so it keeps a justified direct call via
// the afPacketSocket seam. New raw/datagram sockets MUST use linuxsock.Socket.
var allowedFunctions = map[string]string{
	"linuxsock::Socket":          "the SSOT factory that forces SOCK_CLOEXEC",
	"vrrp::openAfPacketReceiver": "pre-existing #2476 site; ORs SOCK_CLOEXEC + pinned by afpacket_cloexec_test.go",
}

// allowedRecvfromFunctions are the production functions permitted to keep a
// direct unix.Recvfrom(...) CALL (#17231). Every other Recvfrom on a socket
// fd must go through linuxsock.PpollRecv, whose ppoll+eventfd wake makes the
// receive cancellable; a bare blocking Recvfrom cannot be woken by close(2)
// and parks on a reused fd number.
//
//   - linuxsock::PpollRecv.Recv IS the primitive: ppoll guarantees
//     readability before the read, so the Recvfrom itself does not park.
//   - nfqueue::Queue.Recv and nfqueue::Queue.waitAck are poll-guarded:
//     each Recvfrom is preceded in the same function by unix.Poll on the
//     same fd with a bounded timeout, so the read cannot park indefinitely
//     and close-to-unblock is never the wake mechanism.
var allowedRecvfromFunctions = map[string]string{
	"linuxsock::PpollRecv.Recv": "the #17231 cancellable-receive primitive; ppoll precedes the read",
	"nfqueue::Queue.Recv":       "poll-guarded: unix.Poll with deadline precedes Recvfrom in the same function",
	"nfqueue::Queue.waitAck":    "poll-guarded: unix.Poll with deadline precedes Recvfrom in the same function",
}

// funcKey formats the receiver-aware allowlist key for a FuncDecl in the
// package at pkgRel (mirrors pkg/fsatomic/canary_test.go).
func funcKey(pkgRel string, fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		recv := recvTypeName(fn.Recv.List[0].Type)
		if recv != "" {
			return pkgRel + "::" + recv + "." + fn.Name.Name
		}
	}
	return pkgRel + "::" + fn.Name.Name
}

// recvTypeName extracts the receiver type name, stripping a leading '*'.
func recvTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvTypeName(t.X)
	case *ast.IndexListExpr:
		return recvTypeName(t.X)
	}
	return ""
}

// pkgRelKey turns a file path under ../ (the pkg/ root) into the
// package-relative key segment: "../cluster/garp.go" -> "cluster".
func pkgRelKey(file string) string {
	rel := filepath.ToSlash(file)
	rel = strings.TrimPrefix(rel, "../")
	return filepath.ToSlash(filepath.Dir(rel))
}

// TestNoDirectUnixSocket is the #2608 socket-factory canary. It walks EVERY
// production (non-test) .go file under pkg/ with go/ast — not grep, so comments
// may mention unix.Socket freely and import aliases of golang.org/x/sys/unix
// are still caught — and flags any direct unix.Socket(...) CALL whose enclosing
// function is not in allowedFunctions.
//
// This makes SOCK_CLOEXEC structural: a new raw/datagram socket added outside
// linuxsock.Socket fails the suite loudly, so the fd-leak hardening (#2476/#2608)
// cannot silently regress.
func TestNoDirectUnixSocket(t *testing.T) {
	var violations []string
	scanned := 0

	root := ".." // pkg/ (this test lives in pkg/linuxsock)
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

		// Resolve the local identifier of the golang.org/x/sys/unix import,
		// including aliases. A dot-import defeats the selector match — reject
		// it outright.
		unixName := ""
		for _, imp := range f.Imports {
			ip, _ := strconv.Unquote(imp.Path.Value)
			if ip != "golang.org/x/sys/unix" {
				continue
			}
			unixName = "unix"
			if imp.Name != nil {
				unixName = imp.Name.Name
				if unixName == "." {
					violations = append(violations,
						fmt.Sprintf("%s: dot-import of unix defeats the Socket canary", path))
				}
			}
		}
		if unixName == "" || unixName == "_" || unixName == "." {
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
				if !ok || sel.Sel.Name != "Socket" {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok || ident.Name != unixName {
					return true
				}
				violations = append(violations, fmt.Sprintf(
					"%s: direct %s.Socket call in %s — use linuxsock.Socket so SOCK_CLOEXEC is forced (the raw fd is otherwise inherited by every fork-exec); see docs/engineering-style.md and #2476/#2608",
					fset.Position(call.Pos()), unixName, funcKey(pkgRel, fn)))
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	// Self-test guard: a walk bug that scans nothing would make this canary
	// vacuously pass.
	t.Logf("scanned %d production .go files under pkg/", scanned)
	if scanned == 0 {
		t.Fatal("canary scanned 0 files — the repo walk is broken")
	}

	for _, v := range violations {
		t.Error(v)
	}
}

// TestNoDirectBlockingRecvfrom is the #17231 receive canary. It walks every
// production (non-test) .go file under pkg/ with go/ast and flags any direct
// unix.Recvfrom(...) call outside allowedRecvfromFunctions. A new blocking
// Recvfrom outside linuxsock.PpollRecv (or a poll-guarded nfqueue read)
// reintroduces the close-does-not-wake defect: the goroutine parks on a
// silent link, leaks with its bound socket, and can answer through a reused
// fd number after cancel.
func TestNoDirectBlockingRecvfrom(t *testing.T) {
	var violations []string
	scanned := 0

	root := ".."
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

		unixName := ""
		for _, imp := range f.Imports {
			ip, _ := strconv.Unquote(imp.Path.Value)
			if ip != "golang.org/x/sys/unix" {
				continue
			}
			unixName = "unix"
			if imp.Name != nil {
				unixName = imp.Name.Name
				if unixName == "." {
					violations = append(violations,
						fmt.Sprintf("%s: dot-import of unix defeats the Recvfrom canary", path))
				}
			}
		}
		if unixName == "" || unixName == "_" || unixName == "." {
			return nil
		}

		pkgRel := pkgRelKey(path)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if _, allowed := allowedRecvfromFunctions[funcKey(pkgRel, fn)]; allowed {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Recvfrom" {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok || ident.Name != unixName {
					return true
				}
				violations = append(violations, fmt.Sprintf(
					"%s: direct %s.Recvfrom call in %s — use linuxsock.PpollRecv so the receive is cancellable via ppoll+eventfd (a bare blocking Recvfrom cannot be woken by close and parks on a reused fd); see #17231/#16669",
					fset.Position(call.Pos()), unixName, funcKey(pkgRel, fn)))
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	t.Logf("scanned %d production .go files under pkg/", scanned)
	if scanned == 0 {
		t.Fatal("canary scanned 0 files — the repo walk is broken")
	}

	for _, v := range violations {
		t.Error(v)
	}
}
