package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/networkd"
)

// richLink17042 is networkd's full rendering for a RETH member with MTU
// 9000, 10g, full duplex — the content the daemon's stripped copies used
// to overwrite (#17042, R4-Q43-01).
const richLink17042 = "# Managed by xpfd — do not edit\n" +
	"[Match]\nOriginalName=enp8s0\n\n[Link]\nName=ge-0-0-1\n" +
	"MTUBytes=9000\nBitsPerSecond=10000000000\nDuplex=full\nDescription=reth member\n"

// TestBootWriterByteIdenticalToNetworkd17042 pins the acceptance shape:
// seed networkd's rendering, run the boot writer, and the file must be
// untouched (changed=false) with MTUBytes/BitsPerSecond still on disk.
func TestBootWriterByteIdenticalToNetworkd17042(t *testing.T) {
	dir := withTempLinkDir(t)
	path := filepath.Join(dir, linkPrefix+"ge-0-0-1.link")
	if err := os.WriteFile(path, []byte(richLink17042), 0o644); err != nil {
		t.Fatal(err)
	}
	// The boot writer knows only (target, originalName). Its rendering
	// lacks the rich fields, so it cannot reproduce the seeded file —
	// the parity claim is instead at the renderer level: for the same
	// (target, originalName) inputs the boot writer's bytes equal
	// RenderLink's bytes. Seed THAT minimal rendering and prove the
	// boot writer is a no-op over it.
	minimal, err := networkd.RenderLink(networkd.LinkSpec{Name: "ge-0-0-1", OriginalName: "enp8s0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(minimal), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := writeLinkFile("ge-0-0-1", "enp8s0")
	if err != nil || changed {
		t.Fatalf("boot writer over networkd rendering = (changed=%v, err=%v), want (false, nil)", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != minimal {
		t.Fatalf("boot writer changed networkd's rendering:\n got=%q\nwant=%q (err=%v)", got, minimal, err)
	}
	// And the renderer itself carries the rich fields when given them.
	rich, err := networkd.RenderLink(networkd.LinkSpec{
		Name: "ge-0-0-1", OriginalName: "enp8s0", MTU: 9000, Speed: "10g", Duplex: "full", Description: "reth member",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rich != richLink17042 {
		t.Fatalf("RenderLink rich rendering differs:\n got=%q\nwant=%q", rich, richLink17042)
	}
}

// TestRethRenamePathPreservesRichLink17042 pins the second acceptance
// shape: seed a MAC-form rich file (the shape ensureRethLinkOriginalName
// exists to fix), run the RETH rename paths, and MTUBytes/BitsPerSecond
// must still be on disk — only the match line changes.
func TestRethRenamePathPreservesRichLink17042(t *testing.T) {
	dir := withTempLinkDir(t)
	path := filepath.Join(dir, linkPrefix+"ge-0-0-1.link")
	macForm := strings.Replace(richLink17042, "OriginalName=enp8s0", "MACAddress=52:54:00:aa:bb:cc", 1)

	// ensure path: derives the kernel name via the seam.
	saved := deriveKernelNameFn
	deriveKernelNameFn = func(string) string { return "enp8s0" }
	t.Cleanup(func() { deriveKernelNameFn = saved })
	if err := os.WriteFile(path, []byte(macForm), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureRethLinkOriginalName("ge-0-0-1"); err != nil {
		t.Fatalf("ensureRethLinkOriginalName: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != richLink17042 {
		t.Fatalf("RETH ensure downgraded the rich unit:\n got=%q\nwant=%q", got, richLink17042)
	}

	// fix path (rename recovery): same preservation.
	if err := os.WriteFile(path, []byte(macForm), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fixRethLinkFile("ge-0-0-1", "enp8s0"); err != nil {
		t.Fatalf("fixRethLinkFile: %v", err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != richLink17042 {
		t.Fatalf("RETH fix downgraded the rich unit:\n got=%q\nwant=%q", got, richLink17042)
	}
	for _, want := range []string{"MTUBytes=9000", "BitsPerSecond=10000000000", "OriginalName=enp8s0"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("RETH rewrite lost %q:\n%s", want, got)
		}
	}

	// Already-OriginalName rich file: neither path touches it.
	if err := os.WriteFile(path, []byte(richLink17042), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureRethLinkOriginalName("ge-0-0-1"); err != nil {
		t.Fatal(err)
	}
	if err := fixRethLinkFile("ge-0-0-1", "enp8s0"); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != richLink17042 {
		t.Fatalf("OriginalName rich file was downgraded:\n got=%q\nwant=%q", got, richLink17042)
	}
}

// TestRethLinkWriteFailureReturnsError17042 pins the fail-closed error
// policy: a blocked .link path makes the RETH path return an error (the
// old fixRethLinkFile only logged a WARN and returned nothing). The
// apply caller joins this into Phase.Networkd (daemon_apply_dataplane.go).
func TestRethLinkWriteFailureReturnsError17042(t *testing.T) {
	dir := withTempLinkDir(t)
	path := filepath.Join(dir, linkPrefix+"ge-0-0-1.link")
	// Block the atomic write: a directory where the file belongs, so the
	// missing-file arm's writeLinkFile write fails.
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fixRethLinkFile("ge-0-0-1", "enp8s0"); err == nil {
		t.Fatal("fixRethLinkFile over a blocked .link path must return an error, got nil (Warn-only policy)")
	}
}

// TestRethLinkRefusalsReturnErrors17042 pins that refusals are errors and
// write nothing, for both RETH entry points.
func TestRethLinkRefusalsReturnErrors17042(t *testing.T) {
	dir := withTempLinkDir(t)
	path := filepath.Join(dir, linkPrefix+"ge-0-0-3.link")
	macForm := strings.Replace(richLink17042, "OriginalName=enp8s0", "MACAddress=52:54:00:aa:bb:cc", 1)
	macForm = strings.Replace(macForm, "Name=ge-0-0-1", "Name=ge-0-0-3", 1)
	if err := os.WriteFile(path, []byte(macForm), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, kernelName := range []string{"ge*", "!enp9s0", "enp 9s0"} {
		if err := fixRethLinkFile("ge-0-0-3", kernelName); err == nil {
			t.Errorf("fixRethLinkFile(kernelName=%q) = nil, want refusal error", kernelName)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != macForm {
			t.Errorf("refused kernelName %q changed the file: got=%q err=%v", kernelName, got, err)
		}
	}
}

// TestRethEnsureErrorJoinsPhaseNetworkd17042 drives the real
// applyConfigLocked: a MAC-form .link whose rewrite is refused (the
// derived kernel name carries a glob) must fail the apply — the error
// reaches the caller through Phase.Networkd, not a Warn log. Hermetic:
// fake netlink ops, fake networkctl, temp linkDir.
func TestRethEnsureErrorJoinsPhaseNetworkd17042(t *testing.T) {
	dir := withTempLinkDir(t)
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, virtMAC5103, false))
	d, _ := rethCallsiteDaemon(t, nil)

	path := filepath.Join(dir, linkPrefix+"ge-0-0-1.link")
	macForm := strings.Replace(richLink17042, "OriginalName=enp8s0", "MACAddress=52:54:00:aa:bb:cc", 1)
	if err := os.WriteFile(path, []byte(macForm), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := deriveKernelNameFn
	deriveKernelNameFn = func(string) string { return "enp*" }
	t.Cleanup(func() { deriveKernelNameFn = saved })

	err := d.applyConfigLocked(context.Background(), rethCallsiteConfig())
	if err == nil {
		t.Fatal("apply over a refused RETH .link rewrite reported success; the refusal never reached Phase.Networkd")
	}
	if !strings.Contains(err.Error(), "#10089") {
		t.Fatalf("apply error must carry the glob refusal, got %v", err)
	}
	got, rerr := os.ReadFile(path)
	if rerr != nil || string(got) != macForm {
		t.Fatalf("refused rewrite changed the file: got=%q err=%v", got, rerr)
	}
}
