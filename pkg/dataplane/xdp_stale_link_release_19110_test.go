package dataplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #19110, the privileged half: the real kernel, a real bpf_link, a real bpffs pin.
//
// The fixture is the SIGKILL shape. A native XDP bpf_link is attached to a veth,
// pinned the way AttachXDP pins it (<dir>/xdp_<ifindex>), and then its fd is
// closed, the way a killed process's fds are, so only the pin holds the link.
// The production sweep then runs, and the cell reads the kernel immediately
// after it.
//
// Unlinking a bpffs pin only schedules the link's release (bpf_destroy_inode ->
// bpf_link_put -> schedule_work; kernel/bpf/syscall.c), and the release takes
// rtnl to detach. So at master the device can still carry the stale link when
// the sweep returns, and an attach issued straight after can overtake the
// release. These are races, so a master run reports k of N; the fix (a
// synchronous BPF_LINK_DETACH before the unpin) must make both counts zero.
//
// They need CAP_BPF, CAP_NET_ADMIN and a bpffs mount, so they skip without
// privilege and are registered in pkg/memlockcensus. make test-memlock-guards
// runs them on a runner VM.

const staleLinkIterations19110 = 50

type staleLinkFixture19110 struct {
	t       *testing.T
	ifindex int
	dir     string
	prog    *ebpf.Program
}

// newStaleLinkFixture19110 runs after the caller's memlock guard. A missing root
// or bpffs SKIPs an ordinary run, but FAILS the privileged leg
// (XPF_REQUIRE_MEMLOCK_GUARDS=1): there, a cell that cannot build its fixture is
// indistinguishable from one that passes.
func newStaleLinkFixture19110(t *testing.T) *staleLinkFixture19110 {
	t.Helper()
	required := os.Getenv("XPF_REQUIRE_MEMLOCK_GUARDS") == "1"
	if os.Geteuid() != 0 {
		if required {
			t.Fatalf("XPF_REQUIRE_MEMLOCK_GUARDS=1 but not root (euid %d): veth and bpffs need it", os.Geteuid())
		}
		t.Skipf("needs root for veth and bpffs (euid %d)", os.Geteuid())
	}
	dir, err := os.MkdirTemp("/sys/fs/bpf", "t19110-")
	if err != nil {
		if required {
			t.Fatalf("XPF_REQUIRE_MEMLOCK_GUARDS=1 but no writable bpffs at /sys/fs/bpf: %v", err)
		}
		t.Skipf("no writable bpffs at /sys/fs/bpf: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.XDP,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 2), // XDP_PASS
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatalf("load XDP_PASS program: %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })

	name := fmt.Sprintf("t19110a%d", os.Getpid()%10000)
	peer := fmt.Sprintf("t19110b%d", os.Getpid()%10000)
	_ = netlink.LinkDel(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}})
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: peer}); err != nil {
		t.Fatalf("create veth %s/%s: %v", name, peer, err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}}) })
	for _, n := range []string{name, peer} {
		l, err := netlink.LinkByName(n)
		if err != nil {
			t.Fatalf("lookup %s: %v", n, err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatalf("set %s up: %v", n, err)
		}
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("lookup %s: %v", name, err)
	}
	return &staleLinkFixture19110{t: t, ifindex: l.Attrs().Index, dir: dir, prog: prog}
}

// leaveStaleLink attaches a native link, pins it, and closes the handle: the
// state a SIGKILLed xpfd leaves behind.
func (f *staleLinkFixture19110) leaveStaleLink() {
	f.t.Helper()
	l, err := link.AttachXDP(link.XDPOptions{Program: f.prog, Interface: f.ifindex, Flags: link.XDPDriverMode})
	if err != nil {
		f.t.Fatalf("fixture: native attach on the veth: %v", err)
	}
	if err := l.Pin(filepath.Join(f.dir, fmt.Sprintf("xdp_%d", f.ifindex))); err != nil {
		_ = l.Close()
		f.t.Fatalf("fixture: pin: %v", err)
	}
	if err := l.Close(); err != nil {
		f.t.Fatalf("fixture: close the handle: %v", err)
	}
	if !f.attached() {
		f.t.Fatal("fixture: after closing its only fd the pinned link is not attached; the pin " +
			"must hold it (that is the SIGKILL state this cell needs)")
	}
}

func (f *staleLinkFixture19110) attached() bool {
	l, err := netlink.LinkByIndex(f.ifindex)
	if err != nil {
		f.t.Fatalf("read IFLA_XDP: %v", err)
	}
	x := l.Attrs().Xdp
	return x != nil && x.Attached
}

// settle waits until the device carries no XDP program, so one iteration's
// leftovers never bleed into the next.
func (f *staleLinkFixture19110) settle() {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for f.attached() {
		if time.Now().After(deadline) {
			f.t.Fatal("fixture: the device still carries XDP 5 s after the sweep")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// P1: when the sweep returns, the stale link must be gone from the device.
func TestStaleXDPLinkIsDetachedWhenTheSweepReturns19110(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("needs the memlock privilege (CAP_BPF/CAP_NET_ADMIN): %v", err)
	}
	f := newStaleLinkFixture19110(t)
	stillAttached := 0
	for i := 0; i < staleLinkIterations19110; i++ {
		f.leaveStaleLink()
		removeUserspaceShimXDPLinkPinsExcept(f.dir, nil)
		if f.attached() {
			stillAttached++
		}
		f.settle()
	}
	t.Logf("stale link still attached right after the sweep returned: %d of %d", stillAttached, staleLinkIterations19110)
	if stillAttached != 0 {
		t.Errorf("in %d of %d iterations the dead process's link was still attached when the sweep "+
			"returned: removing the pin only schedules the release, so the attach that follows races "+
			"it (#19110)", stillAttached, staleLinkIterations19110)
	}
}

// P2: a native attach issued immediately after the sweep must never see the
// stale link.
func TestNativeAttachAfterSweepNeverSeesTheStaleLink19110(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("needs the memlock privilege (CAP_BPF/CAP_NET_ADMIN): %v", err)
	}
	f := newStaleLinkFixture19110(t)
	busy, other := 0, 0
	for i := 0; i < staleLinkIterations19110; i++ {
		f.leaveStaleLink()
		removeUserspaceShimXDPLinkPinsExcept(f.dir, nil)
		l, err := link.AttachXDP(link.XDPOptions{Program: f.prog, Interface: f.ifindex, Flags: link.XDPDriverMode})
		switch {
		case err == nil:
			_ = l.Close()
		case errors.Is(err, unix.EBUSY) || errors.Is(err, unix.EEXIST):
			busy++
		default:
			other++
			t.Logf("iteration %d: unexpected attach error: %v", i, err)
		}
		f.settle()
	}
	t.Logf("native attach right after the sweep: occupied %d, other errors %d, of %d", busy, other, staleLinkIterations19110)
	if busy != 0 {
		t.Errorf("in %d of %d iterations a native attach issued right after the sweep found the dead "+
			"process's link still attached (EBUSY/EEXIST) (#19110)", busy, staleLinkIterations19110)
	}
	if other != 0 {
		t.Errorf("%d unexpected attach errors (see log)", other)
	}
}

// P3: the refusal comes from an UPPER device. A macvlan on the veth carries an
// XDP link, so the kernel refuses any XDP attach on the lower with EEXIST
// ("Cannot attach when an upper device already has a program", net/core/dev.c).
// That occupant is invisible to a poll of the target's own IFLA_XDP, which is
// why the design retries the attach itself instead of polling.
//
// The #18740 seam hands each attach to the REAL kernel (a trivial XDP_PASS
// program attached with the requested mode) and records it, so the errno is the
// kernel's own, not a script's.
//
// Expected at the fix: the pass gives up within the budget with the kernel's
// EEXIST still wrapped, makes no generic attempt, and its diagnostic names the
// upper device. At master: the first EEXIST sends the lower to generic.
func TestUpperDeviceRefusalIsNotAGenericFallback19110(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("needs the memlock privilege (CAP_BPF/CAP_NET_ADMIN): %v", err)
	}
	f := newStaleLinkFixture19110(t)

	lower, err := netlink.LinkByIndex(f.ifindex)
	if err != nil {
		t.Fatalf("lookup the veth: %v", err)
	}
	upperName := fmt.Sprintf("t19110m%d", os.Getpid()%10000)
	mv := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{Name: upperName, ParentIndex: lower.Attrs().Index},
		Mode:      netlink.MACVLAN_MODE_BRIDGE,
	}
	if err := netlink.LinkAdd(mv); err != nil {
		t.Fatalf("create macvlan upper: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(mv) })
	upper, err := netlink.LinkByName(upperName)
	if err != nil {
		t.Fatalf("lookup macvlan: %v", err)
	}
	if err := netlink.LinkSetUp(upper); err != nil {
		t.Fatalf("set macvlan up: %v", err)
	}
	ul, err := link.AttachXDP(link.XDPOptions{Program: f.prog, Interface: upper.Attrs().Index, Flags: link.XDPGenericMode})
	if err != nil {
		t.Fatalf("fixture: generic XDP on the macvlan upper: %v", err)
	}
	t.Cleanup(func() { _ = ul.Close() })

	var trace []string
	seam := func(op string, ifindex int, generic bool) (bool, error) {
		mode := "native"
		if generic {
			mode = "generic"
		}
		trace = append(trace, fmt.Sprintf("%s/%d/%s", op, ifindex, mode))
		if op != "attach" {
			return true, nil
		}
		flags := link.XDPDriverMode
		if generic {
			flags = link.XDPGenericMode
		}
		l, err := link.AttachXDP(link.XDPOptions{Program: f.prog, Interface: ifindex, Flags: flags})
		if err != nil {
			return true, fmt.Errorf("attach XDP to ifindex %d: %w", ifindex, err)
		}
		_ = l.Close()
		return true, nil
	}
	aerr := runAttachWithSeam19110(t, seam, f.ifindex)
	if aerr == nil {
		t.Fatalf("the attach succeeded although the upper device carries XDP (trace %v)", trace)
	}
	if !errors.Is(aerr, unix.EEXIST) {
		t.Errorf("the kernel's EEXIST is not wrapped in the result: %v", aerr)
	}
	for _, o := range trace {
		if o == fmt.Sprintf("attach/%d/generic", f.ifindex) {
			t.Errorf("a generic attempt after an upper-device refusal; the kernel refuses generic for the "+
				"same reason, so it can only fail or race (trace %v)", trace)
			break
		}
	}
	if !strings.Contains(aerr.Error(), upperName) {
		t.Errorf("the give-up diagnostic does not name the upper device %s that carries XDP: %v", upperName, aerr)
	}
}

// P4 (R23 P3-6): P1 and P2 drive the SWEEP, but production never sweeps a
// configured interface's pin; its path is the attach pass's per-interface
// reclaim. Here a stale native link is left pinned at <linkPinPath>/xdp_<veth>,
// the SIGKILL shape, and attachUserspaceShimXDP runs on that interface. The
// #18740 seam hands each attach to the REAL kernel. Every iteration must
// succeed on its FIRST native attempt: no EBUSY, no EEXIST, no retry.
func TestReclaimBeforeAttachLeavesTheKernelFree19110(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("needs the memlock privilege (CAP_BPF/CAP_NET_ADMIN): %v", err)
	}
	f := newStaleLinkFixture19110(t)
	t.Cleanup(SetLinkPinPathForTest(f.dir))
	var natives, refusals int
	t.Cleanup(SetXDPTransitionSeamForTest(func(op string, ifindex int, generic bool) (bool, error) {
		if op != "attach" {
			return true, nil
		}
		if !generic {
			natives++
		}
		flags := link.XDPDriverMode
		if generic {
			flags = link.XDPGenericMode
		}
		l, err := link.AttachXDP(link.XDPOptions{Program: f.prog, Interface: ifindex, Flags: flags})
		if err != nil {
			if errors.Is(err, unix.EBUSY) || errors.Is(err, unix.EEXIST) {
				refusals++
			}
			return true, fmt.Errorf("attach XDP to ifindex %d: %w", ifindex, err)
		}
		_ = l.Close()
		return true, nil
	}))
	for i := 0; i < staleLinkIterations19110; i++ {
		f.leaveStaleLink()
		natives, refusals = 0, 0
		err := New().attachUserspaceShimXDP(&CompileResult{pendingXDP: []int{f.ifindex}})
		if err != nil || natives != 1 || refusals != 0 {
			t.Fatalf("iteration %d: err=%v native attempts=%d refusals=%d; the per-interface reclaim must "+
				"leave the kernel free for ONE native attach (#19110)", i, err, natives, refusals)
		}
		f.settle()
	}
}

// P5 (Codex): the identity repair against REAL kernel link IDs. The #9847
// fixture replaces the verifier, so no other cell sees a real link ID: a "fix"
// comparing link TYPES instead of IDs passes every faked cell. Here the
// registered link A is real. A pin at A's path is first A's own, which must be
// kept, and then another real XDP link B's, which has the same type but a
// different ID and must be replaced by A's pin.
func TestRepairUsesRealLinkIdentity19110(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("needs the memlock privilege (CAP_BPF/CAP_NET_ADMIN): %v", err)
	}
	f := newStaleLinkFixture19110(t)
	t.Cleanup(SetLinkPinPathForTest(f.dir))
	peer, err := netlink.LinkByName(strings.Replace(mustLinkName19110(t, f.ifindex), "t19110a", "t19110b", 1))
	if err != nil {
		t.Fatalf("fixture: peer veth: %v", err)
	}
	a, err := link.AttachXDP(link.XDPOptions{Program: f.prog, Interface: f.ifindex, Flags: link.XDPDriverMode})
	if err != nil {
		t.Fatalf("fixture: link A: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := link.AttachXDP(link.XDPOptions{Program: f.prog, Interface: peer.Attrs().Index, Flags: link.XDPGenericMode})
	if err != nil {
		t.Fatalf("fixture: link B: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	pin := filepath.Join(f.dir, fmt.Sprintf("xdp_%d", f.ifindex))
	id := func(l link.Link) link.ID {
		i, err := l.Info()
		if err != nil {
			t.Fatalf("link info: %v", err)
		}
		return i.ID
	}
	pinnedID := func() link.ID {
		l, err := link.LoadPinnedLink(pin, nil)
		if err != nil {
			t.Fatalf("load the pin: %v", err)
		}
		defer l.Close()
		return id(l)
	}

	if err := a.Pin(pin); err != nil {
		t.Fatalf("fixture: pin A: %v", err)
	}
	if err := ensureXDPLinkPinned(f.ifindex, a); err != nil || pinnedID() != id(a) {
		t.Fatalf("A's own pin: ensure=%v pinned=%d, want A's pin kept (id %d)", err, pinnedID(), id(a))
	}

	if err := os.Remove(pin); err != nil {
		t.Fatalf("fixture: unlink A's pin: %v", err)
	}
	if err := b.Pin(pin); err != nil {
		t.Fatalf("fixture: pin B at A's path: %v", err)
	}
	if err := ensureXDPLinkPinned(f.ifindex, a); err != nil {
		t.Fatalf("ensure over B's pin: %v", err)
	}
	if got := pinnedID(); got != id(a) {
		t.Errorf("after the repair the pin names link %d, want A (%d): a pin naming another XDP link "+
			"(B, %d, same type) was trusted as this link's", got, id(a), id(b))
	}
}

func mustLinkName19110(t *testing.T, ifindex int) string {
	t.Helper()
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		t.Fatalf("link %d: %v", ifindex, err)
	}
	return l.Attrs().Name
}
