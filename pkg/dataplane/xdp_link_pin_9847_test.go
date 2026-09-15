package dataplane

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// #9847: every compile removed the XDP link pins and AttachXDP never re-pinned
// a registered link, so a restart detached the shim. The cells below pin each
// link of the fix; the kernel half of the property ("a link survives its last
// handle close while pinned") is cilium's documented bpf_link invariant
// (link.Link.Close: "The link will be broken unless it has been successfully
// pinned"), so the composition — pins survive compiles, missing pins are
// re-pinned, Close reports what is still unpinned — is the whole mechanism.

// pinTrackingLink9847 is a link.Link that models the kernel pin AND cilium's
// cached pin path (RawLink.pinnedPath, ebpf v0.20.0): Pin to the already-
// cached path is a nil no-op that writes nothing
// (internal/sys/pinning_other.go), and Unpin forgets the cached path.
// pinErr models Pin failing after a successful attach (AttachXDP logs and
// continues); pinSilent models a Pin that reports success while writing
// nothing. events records Pin/Close order for the repair-before-release cell.
type pinTrackingLink9847 struct {
	link.Link
	pinCalls   int
	pinErr     error
	pinSilent  bool
	pinnedPath string
	closed     bool
	events     []string
}

func (f *pinTrackingLink9847) Pin(path string) error {
	f.pinCalls++
	f.events = append(f.events, "pin")
	if f.pinErr != nil {
		return f.pinErr
	}
	if f.pinnedPath == path {
		return nil // cilium cached-path no-op: success, nothing written
	}
	if f.pinSilent {
		return nil
	}
	if err := os.WriteFile(path, []byte("pin"), 0600); err != nil {
		return err
	}
	f.pinnedPath = path
	return nil
}

func (f *pinTrackingLink9847) Unpin() error {
	if f.pinnedPath == "" {
		return nil
	}
	_ = os.Remove(f.pinnedPath)
	f.pinnedPath = ""
	return nil
}

func (f *pinTrackingLink9847) Close() error {
	f.events = append(f.events, "close")
	f.closed = true
	return nil
}

// withTempPinDir9847 redirects linkPinPath at a temp dir for one test. The
// package has t.Parallel AST-inventory tests, but none of them execute the
// pin paths (they never call Attach/Detach/Close or the sweep), so the swap
// is race-free the same way the existing hook swaps are.
func withTempPinDir9847(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := linkPinPath
	linkPinPath = dir
	t.Cleanup(func() { linkPinPath = old })
	return dir
}

func seedPin9847(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("pin"), 0600); err != nil {
		t.Fatalf("seed pin %s: %v", name, err)
	}
}

func pinExists9847(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

func TestRemoveUserspaceShimXDPLinkPinsExcept_KeepsRegistered_9847(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"xdp_7", "xdp_9", "xdp_bogus", "xdp_", "tc_7", "notes.txt"} {
		seedPin9847(t, dir, name)
	}

	removeUserspaceShimXDPLinkPinsExcept(dir, map[int]bool{7: true})

	for _, name := range []string{"xdp_7", "tc_7", "notes.txt"} {
		if !pinExists9847(dir, name) {
			t.Errorf("%s removed, want kept (registered link / non-xdp_* name)", name)
		}
	}
	for _, name := range []string{"xdp_9", "xdp_bogus", "xdp_"} {
		if pinExists9847(dir, name) {
			t.Errorf("%s kept, want removed (stale or unparseable link pin)", name)
		}
	}
}

func TestRemoveUserspaceShimXDPLinkPinsExcept_NilKeepSweepsAll_9847(t *testing.T) {
	dir := t.TempDir()
	seedPin9847(t, dir, "xdp_7")
	seedPin9847(t, dir, "tc_3")

	// Fresh-boot shape: empty registry, every xdp_* pin is stale.
	removeUserspaceShimXDPLinkPinsExcept(dir, nil)

	if pinExists9847(dir, "xdp_7") {
		t.Error("xdp_7 kept with empty registry, want removed (fresh-attach rationale)")
	}
	if !pinExists9847(dir, "tc_3") {
		t.Error("tc_3 removed, want kept (never an xdp_* pin)")
	}
}

func TestRemoveUserspaceShimXDPLinkPinsExcept_MissingDir_9847(t *testing.T) {
	// Best-effort, as at the original site: no dir, no-op, no panic.
	removeUserspaceShimXDPLinkPinsExcept(filepath.Join(t.TempDir(), "absent"), map[int]bool{7: true})
}

func TestRemoveUserspaceShimXDPLinkPins_KeepsRegisteredLinks_9847(t *testing.T) {
	dir := withTempPinDir9847(t)
	seedPin9847(t, dir, "xdp_7")
	seedPin9847(t, dir, "xdp_9")

	// Second-compile shape: ifindex 7 attached by an earlier compile and
	// still registered; xdp_9 is a stale pin from a previous process.
	m := New()
	m.SetLinkForTest(7, &pinTrackingLink9847{}, nil)
	m.removeUserspaceShimXDPLinkPins()

	if !pinExists9847(dir, "xdp_7") {
		t.Error("xdp_7 removed for a registered link — the next Close detaches ifindex 7 (#9847)")
	}
	if pinExists9847(dir, "xdp_9") {
		t.Error("xdp_9 kept for an unregistered ifindex, want swept (fresh attach)")
	}
}

func TestEnsureXDPLinkPinned_RepinsMissing_9847(t *testing.T) {
	dir := withTempPinDir9847(t)
	fake := &pinTrackingLink9847{}

	if err := ensureXDPLinkPinned(5, fake); err != nil {
		t.Fatalf("ensure missing pin = %v, want nil", err)
	}
	if fake.pinCalls != 1 {
		t.Fatalf("Pin calls = %d, want 1 (missing pin must be re-pinned)", fake.pinCalls)
	}
	if !pinExists9847(dir, "xdp_5") {
		t.Error("xdp_5 still missing after re-pin")
	}

	// Second call is a no-op: the pin is present now.
	if err := ensureXDPLinkPinned(5, fake); err != nil {
		t.Fatalf("ensure present pin = %v, want nil", err)
	}
	if fake.pinCalls != 1 {
		t.Errorf("Pin calls = %d after pin present, want 1 (no re-pin over EEXIST)", fake.pinCalls)
	}
}

func TestEnsureXDPLinkPinned_SkipsPresent_9847(t *testing.T) {
	dir := withTempPinDir9847(t)
	seedPin9847(t, dir, "xdp_5")
	fake := &pinTrackingLink9847{}

	if err := ensureXDPLinkPinned(5, fake); err != nil {
		t.Fatalf("ensure present pin = %v, want nil", err)
	}
	if fake.pinCalls != 0 {
		t.Errorf("Pin calls = %d with pin present, want 0", fake.pinCalls)
	}
}

func TestEnsureXDPLinkPinned_NilLink_9847(t *testing.T) {
	withTempPinDir9847(t)
	// SetLinkForTest records nil as-is; the re-pin must not dereference it.
	if err := ensureXDPLinkPinned(5, nil); err != nil {
		t.Fatalf("ensure nil link = %v, want nil", err)
	}
}

func TestEnsureXDPLinkPinned_PinFailureWarns_9847(t *testing.T) {
	dir := withTempPinDir9847(t)
	fake := &pinTrackingLink9847{pinErr: errors.New("bpffs read-only")}

	err := ensureXDPLinkPinned(5, fake)

	if err == nil {
		t.Fatal("ensure with failing Pin = nil, want error")
	}
	if fake.pinCalls != 1 {
		t.Fatalf("Pin calls = %d, want 1 (attempted despite failure)", fake.pinCalls)
	}
	if pinExists9847(dir, "xdp_5") {
		t.Error("xdp_5 exists after failed Pin, want still missing (Close must report degraded)")
	}
}

// TestEnsureXDPLinkPinned_RepinsAfterPinDisappeared_9847 is the GPT-1
// regression: a link pinned BEFORE its pathname disappeared carries cilium's
// cached pin path, so a naive Pin to the same path is a nil no-op
// (internal/sys/pinning_other.go: currentPath == newPath) while the pin
// stays absent. The re-pin must forget (Unpin) before Pin, and the post-Pin
// stat is the verdict either way.
func TestEnsureXDPLinkPinned_RepinsAfterPinDisappeared_9847(t *testing.T) {
	dir := withTempPinDir9847(t)
	fake := &pinTrackingLink9847{}

	pinFile := filepath.Join(dir, "xdp_5")
	if err := fake.Pin(pinFile); err != nil {
		t.Fatalf("setup Pin: %v", err)
	}
	if err := os.Remove(pinFile); err != nil {
		t.Fatalf("setup remove: %v", err)
	}

	if err := ensureXDPLinkPinned(5, fake); err != nil {
		t.Fatalf("ensure after disappearance = %v, want nil (re-pinned)", err)
	}
	if !pinExists9847(dir, "xdp_5") {
		t.Fatal("xdp_5 still missing: Pin no-opped on the stale cached path")
	}
}

func TestEnsureXDPLinkPinned_SilentPinFailure_9847(t *testing.T) {
	withTempPinDir9847(t)
	fake := &pinTrackingLink9847{pinSilent: true}

	// Pin reports success while writing nothing: only the post-Pin stat can
	// catch it, and it must come back as an error, not a success log.
	if err := ensureXDPLinkPinned(5, fake); err == nil {
		t.Fatal("ensure with silent Pin = nil, want error (nil Pin with no file is failure)")
	}
}

func TestAttachXDP_AlreadyAttachedRepinsMissingPin_9847(t *testing.T) {
	dir := withTempPinDir9847(t)

	m := New()
	m.loaded.Store(true)
	m.SelectUserspaceXDPShimEntryProgram()
	m.mu.Lock()
	m.programs[userspaceShimEntryProg] = &ebpf.Program{}
	m.mu.Unlock()
	fake := &pinTrackingLink9847{}
	m.SetLinkForTest(7, fake, nil)

	err := m.AttachXDP(7, false)

	if err == nil || !strings.Contains(err.Error(), "already attached") {
		t.Fatalf("AttachXDP = %v, want the unchanged \"already attached\" error", err)
	}
	if fake.pinCalls != 1 {
		t.Fatalf("Pin calls = %d, want 1 (short-circuit must re-pin the missing pin)", fake.pinCalls)
	}
	if !pinExists9847(dir, "xdp_7") {
		t.Error("xdp_7 still missing after already-attached re-pin")
	}
}

func TestUnpinnedXDPLinks_9847(t *testing.T) {
	dir := t.TempDir()
	seedPin9847(t, dir, "xdp_7")

	links := map[int]link.Link{9: &pinTrackingLink9847{}, 7: &pinTrackingLink9847{}, 3: nil}
	missing := unpinnedXDPLinks(dir, links)

	if len(missing) != 2 || missing[0] != 3 || missing[1] != 9 {
		t.Fatalf("unpinned = %v, want [3 9] sorted (nil-link membership still counts)", missing)
	}
	if got := unpinnedXDPLinks(dir, nil); len(got) != 0 {
		t.Fatalf("unpinned(nil) = %v, want empty", got)
	}
}

func TestCloseReportsDegradedOnUnpinnedXDPLink_9847(t *testing.T) {
	withTempPinDir9847(t)

	m := New()
	fake := &pinTrackingLink9847{pinErr: errors.New("bpffs read-only")}
	m.SetLinkForTest(11, fake, nil)

	err := m.Close()

	if err == nil || !strings.Contains(err.Error(), "11") {
		t.Fatalf("Close = %v, want error naming ifindex 11 (unrepairable link detached)", err)
	}
	if !fake.closed {
		t.Error("Close did not close the link handle (handles close either way)")
	}
	if len(m.XDPLinks()) != 1 {
		t.Error("Close cleared the xdpLinks membership — retention is the hitless posture")
	}
	if len(fake.events) != 2 || fake.events[0] != "pin" || fake.events[1] != "close" {
		t.Errorf("events = %v, want [pin close] (repair runs before handle release)", fake.events)
	}
}

func TestCloseSucceedsWhenXDPLinksPinned_9847(t *testing.T) {
	dir := withTempPinDir9847(t)
	seedPin9847(t, dir, "xdp_11")

	m := New()
	m.SetLinkForTest(11, &pinTrackingLink9847{}, nil)

	if err := m.Close(); err != nil {
		t.Fatalf("Close with pinned link = %v, want nil", err)
	}
}

func TestCloseRepinsMissingPinBeforeClosing_9847(t *testing.T) {
	dir := withTempPinDir9847(t)

	m := New()
	fake := &pinTrackingLink9847{}
	m.SetLinkForTest(11, fake, nil)

	if err := m.Close(); err != nil {
		t.Fatalf("Close with repairable link = %v, want nil (re-pin before release)", err)
	}
	if !pinExists9847(dir, "xdp_11") {
		t.Error("xdp_11 still missing after Close: repair did not re-pin before release")
	}
	if len(fake.events) != 2 || fake.events[0] != "pin" || fake.events[1] != "close" {
		t.Errorf("events = %v, want [pin close] (repair runs before handle release)", fake.events)
	}
}
