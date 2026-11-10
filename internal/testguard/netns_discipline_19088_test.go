package testguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func disciplineOf19088(t *testing.T, files map[string]string) error {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return CheckNetnsThreadDiscipline(dir)
}

// The rule each guarded package's own cell enforces, against fixtures that
// break it and fixtures that keep it.
func TestNetnsThreadDisciplineRules19088(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // "" = clean; otherwise a substring of the finding
	}{
		{"raw unlock after a switch", `package p
import ("runtime"; "github.com/vishvananda/netns")
func f(h netns.NsHandle) { runtime.LockOSThread(); _ = netns.Set(h); runtime.UnlockOSThread() }
`, "runtime.UnlockOSThread"},
		{"aliased imports", `package p
import (rt "runtime"; ns "github.com/vishvananda/netns")
func f() { rt.LockOSThread(); _, _ = ns.New() }
`, "runtime.LockOSThread"},
		{"raw setns", `package p
import ("runtime"; "golang.org/x/sys/unix")
func f(fd int) { runtime.LockOSThread(); defer runtime.UnlockOSThread(); _ = unix.Setns(fd, unix.CLONE_NEWNET) }
`, "runtime.UnlockOSThread"},
		{"leader namespace path", `package p
import "os"
func f() { _, _ = os.Open("/proc/self/ns/net") }
`, "/proc/self/ns/"},
		{"locks without a switch", `package p
import "runtime"
func f() { runtime.LockOSThread(); defer runtime.UnlockOSThread() }
`, ""},
		{"switch under the helpers", `package p
import ("github.com/psaab/xpf/internal/testguard"; "github.com/vishvananda/netns")
func f(h netns.NsHandle) error { n, err := testguard.LockThreadNetns(); if err != nil { return err }; _ = netns.Set(h); return n.Release() }
`, ""},
		{"thread-self path", `package p
import "os"
func f() { _, _ = os.Readlink("/proc/thread-self/ns/net") }
`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := disciplineOf19088(t, map[string]string{"a_test.go": tc.src})
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("clean fixture reported: %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("fixture breaking the rule passed")
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("finding %v does not name %q", err, tc.want)
			}
		})
	}
}

// A directory the check cannot read is not clean.
func TestNetnsThreadDisciplineFailsClosed19088(t *testing.T) {
	if err := CheckNetnsThreadDiscipline(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing package directory passed the discipline check")
	}
	if err := disciplineOf19088(t, map[string]string{"a_test.go": "package p\nfunc f( {"}); err == nil {
		t.Fatal("an unparsable test file passed the discipline check")
	}
}
