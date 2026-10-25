package daemon

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// occupyLifelineNetworkTarget makes the fxp0 .network target unwritable the
// way the source probe did: the target path is a DIRECTORY, so the atomic
// rename onto it fails. It stands in for ENOSPC/EROFS/EIO under
// /etc/systemd/network at the moment of the bootstrap rename.
func occupyLifelineNetworkTarget16682(t *testing.T, linkDir string) string {
	t.Helper()
	netPath := filepath.Join(linkDir, linkPrefix+"fxp0.network")
	if err := os.Mkdir(netPath, 0o755); err != nil {
		t.Fatalf("occupy fxp0 .network target: %v", err)
	}
	return netPath
}

// enp5s0RenameLifeline16682 points the lifeline seams at an index-0 NIC still
// under its kernel name enp5s0 carrying a static 192.0.2.10/24 and a
// 192.0.2.1 default route, selected BY DEFAULT ROUTE — the issue's trace.
// Unlike staticLifelineSeams (lifeline == fxp0, which exercises no rename),
// the rename seam here really would run, so *st.renamed is the witness.
func enp5s0RenameLifeline16682(t *testing.T) lifelineSeamState {
	t.Helper()
	st := staticLifelineSeams(t)
	detectLifelineInterfaceFn = func() (string, bool, error) { return "enp5s0", true, nil }
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		return []pciNIC{{sortKey: 0, busAddr: "0000:05:00.0", name: "enp5s0"}}, nil
	}
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{staticAddr("192.0.2.10/24")}, nil
	}
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{{Gw: net.ParseIP("192.0.2.1")}}, nil
		}
		return nil, nil
	}
	return st
}

// TestLifelineNetworkWriteFailureRefusesRename16682 is the #16682 witness,
// with both controls.
//
// writeBootstrapLifelineNetwork laundered a failed .network write into
// (false, nil) — the #5842 shape: (false, nil) already means "already
// correct, nothing to do", so the caller in setupBootstrapLifeline, which
// refuses only on a non-nil error, proceeded to write the .link, rename
// (cycle) enp5s0 to fxp0 and reload. The host's name-keyed config no longer
// matched, no xpf fxp0 .network existed to re-address the renamed NIC, and
// the link cycle flushed the default route — a bootstrap box reachable only
// over that NIC went console-only on a storage fault, when the documented
// posture is to change nothing.
//
// WITNESS (target occupied, write fails): renamed=false, reloaded=false, no
// .link, .network target untouched, and writeBootstrapLifelineNetwork
// returns (false, non-nil).
// CONTROL (write succeeds): .network carries the static snapshot, .link
// records OriginalName=enp5s0, renamed=true, reloaded=true.
// CONTROL (observation fails): renamed=false, reloaded=false, no files —
// the pre-existing #6789 refusal, unchanged.
//
// FAIL-ON-REVERT: returning (false, nil) on the write error again reds the
// witness's renamed/reloaded/.link assertions and its direct error check.
func TestLifelineNetworkWriteFailureRefusesRename16682(t *testing.T) {
	t.Run("witness-write-fails-refuses", func(t *testing.T) {
		st := enp5s0RenameLifeline16682(t)
		netPath := occupyLifelineNetworkTarget16682(t, st.linkDir)

		// Unit-bind the producer first: the failed write must surface.
		if changed, err := writeBootstrapLifelineNetwork("enp5s0", true); err == nil || changed {
			t.Fatalf("writeBootstrapLifelineNetwork on a failed write = (changed=%v, err=%v), "+
				"want (false, non-nil): (false, nil) is the #5842 laundering this closes (#16682)",
				changed, err)
		}

		d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
		d.setupBootstrapLifeline()

		if *st.renamed {
			t.Error("the management NIC was RENAMED after the fxp0 .network write FAILED. " +
				"The rename cycles the link and flushes the default route, and with no fxp0 " +
				".network to re-address it the box is console-only (#16682)")
		}
		if *st.reloaded {
			t.Error("networkctl reload ran after a failed fxp0 .network write; every other " +
				"failure in setupBootstrapLifeline refuses without touching anything")
		}
		linkPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.link")
		if _, err := os.Stat(linkPath); err == nil {
			t.Errorf("an fxp0 .link was written after the .network write failed (%s); the refusal "+
				"must happen before the .link write, the rename and the reload", linkPath)
		}
		if fi, err := os.Stat(netPath); err != nil || !fi.IsDir() {
			t.Errorf("the occupied fxp0 .network target must be untouched: stat=%v err=%v", fi, err)
		}
		if got := filesIn(t, st.linkDir); len(got) != 1 || got[0] != linkPrefix+"fxp0.network" {
			t.Errorf("only the pre-existing occupied target may remain, got %v", got)
		}
	})

	t.Run("control-write-succeeds-renames", func(t *testing.T) {
		st := enp5s0RenameLifeline16682(t)

		d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
		d.setupBootstrapLifeline()

		netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
		data, err := os.ReadFile(netPath)
		if err != nil {
			t.Fatalf("a successful write must produce the bootstrap fxp0 .network: %v", err)
		}
		got := string(data)
		if !strings.Contains(got, "Address=192.0.2.10/24") || !strings.Contains(got, "Gateway=192.0.2.1") {
			t.Errorf("the static snapshot must be written; got:\n%s", got)
		}
		linkPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.link")
		link, err := os.ReadFile(linkPath)
		if err != nil || !strings.Contains(string(link), "OriginalName=enp5s0") {
			t.Errorf("the .link must record OriginalName=enp5s0, got %q err=%v", link, err)
		}
		if !*st.renamed {
			t.Error("a successful .network write must still rename enp5s0 to fxp0; refusing " +
				"unconditionally would strand every bootstrap box under its kernel name")
		}
		if !*st.reloaded {
			t.Error("a successful .network write must still reload networkd")
		}
	})

	t.Run("control-observation-fails-refuses", func(t *testing.T) {
		st := enp5s0RenameLifeline16682(t)
		lifelineLinkByName = func(string) (netlink.Link, error) {
			return nil, errors.New("injected: netlink observation failure")
		}

		d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
		d.setupBootstrapLifeline()

		if *st.renamed {
			t.Error("renamed after a failed addressing observation; the #6789 refusal must be unchanged")
		}
		if *st.reloaded {
			t.Error("reloaded after a failed addressing observation; the #6789 refusal must be unchanged")
		}
		if got := filesIn(t, st.linkDir); len(got) != 0 {
			t.Errorf("a failed observation must write nothing, got %v", got)
		}
	})
}
