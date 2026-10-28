// #2733: a NAT'd session's reverse companion is installed keyed on the
// TRANSLATED tuple (val.ReverseKey), not the naive src/dst swap of the
// forward key. The session clear MUST delete val.ReverseKey, otherwise a
// NAT'd-session clear removes only the forward entry and leaks the real
// reverse companion. These tests record the exact keys DeleteSession is
// called with and assert val.ReverseKey is deleted (and the naive swap is
// not). Fail-on-revert: restoring the naive-swap key construction deletes
// the wrong key and the leak assertion goes RED.
package cli

import (
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
)

// recordingClearCLIDP records every key passed to DeleteSession /
// DeleteSessionV6 so a test can assert which reverse-companion key the
// clear targeted. It embeds *dataplane.Manager to satisfy cliRuntime;
// only the session methods are overridden.
type recordingClearCLIDP struct {
	*dataplane.Manager

	v4Sessions map[dataplane.SessionKey]dataplane.SessionValue
	v6Sessions map[dataplane.SessionKeyV6]dataplane.SessionValueV6

	deletedV4 []dataplane.SessionKey
	deletedV6 []dataplane.SessionKeyV6

	// missingV4 keys report not-found on delete, modelling the dataplane
	// returning ErrKeyNotExist for a key that does not exist (e.g. the
	// naive swap of a NAT'd session). A delete of any other key succeeds.
	missingV4 map[dataplane.SessionKey]bool
}

func (d *recordingClearCLIDP) IsLoaded() bool { return true }

func (d *recordingClearCLIDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for k, v := range d.v4Sessions {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (d *recordingClearCLIDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for k, v := range d.v6Sessions {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

// #4886: the bounded CLI clear prefers the cursor path (cliSessionCursor). This
// fixture's table is well under cliClearFilteredBatch, so it clears in one chunk;
// the cursor is irrelevant, so delegate to the full-scan iterators.
func (d *recordingClearCLIDP) IterateSessionsFrom(_ *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return d.IterateSessions(fn)
}

func (d *recordingClearCLIDP) IterateSessionsV6From(_ *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return d.IterateSessionsV6(fn)
}

func (d *recordingClearCLIDP) DeleteSession(key dataplane.SessionKey) error {
	d.deletedV4 = append(d.deletedV4, key)
	if d.missingV4[key] {
		return ebpf.ErrKeyNotExist
	}
	return nil
}

func (d *recordingClearCLIDP) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	d.deletedV6 = append(d.deletedV6, key)
	return nil
}

func (d *recordingClearCLIDP) ClearAllSessions() (int, int, error) { return 0, 0, nil }

func newRecordingCLI(t *testing.T, dp cliRuntime) *CLI {
	t.Helper()
	return &CLI{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    dp,
	}
}

func containsV4(keys []dataplane.SessionKey, want dataplane.SessionKey) bool {
	for _, k := range keys {
		if k == want {
			return true
		}
	}
	return false
}

// A NAT'd (SNAT) session: forward key and val.ReverseKey are the TRUE
// dual-entry pair. The naive src/dst swap of the forward key is a
// DIFFERENT, non-existent tuple. The clear must delete val.ReverseKey and
// must NOT delete the naive swap. Reverting the fix (naive-swap key) makes
// this RED: val.ReverseKey is left behind (leak) and the naive swap is
// deleted instead.
func TestClearFilteredSessionsDeletesTranslatedReverseKey(t *testing.T) {
	// Forward: 10.0.1.10:1000 -> 8.8.8.8:443  (host-order ports shown,
	// stored network-order; exact byte values are irrelevant to a
	// protocol-only filter — only key identity matters).
	fwd := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 1, 10},
		DstIP:    [4]byte{8, 8, 8, 8},
		SrcPort:  0x03e8, // 1000
		DstPort:  0x01bb, // 443
	}
	// TRANSLATED reverse companion (SNAT public src 203.0.113.5:50000):
	// 8.8.8.8:443 -> 203.0.113.5:50000. This is val.ReverseKey.
	translatedRev := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{8, 8, 8, 8},
		DstIP:    [4]byte{203, 0, 113, 5},
		SrcPort:  0x01bb,
		DstPort:  0xc350, // 50000
	}
	// The naive src/dst swap of the forward key — the WRONG key the buggy
	// clear computed. It must never be deleted (and does not exist).
	naiveSwap := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    fwd.DstIP,
		DstIP:    fwd.SrcIP,
		SrcPort:  fwd.DstPort,
		DstPort:  fwd.SrcPort,
	}

	val := dataplane.SessionValue{
		Flags:      dataplane.SessFlagSNAT,
		ReverseKey: translatedRev,
	}

	dp := &recordingClearCLIDP{
		Manager:    dataplane.New(),
		v4Sessions: map[dataplane.SessionKey]dataplane.SessionValue{fwd: val},
		missingV4:  map[dataplane.SessionKey]bool{naiveSwap: true},
	}
	c := newRecordingCLI(t, dp)
	if err := c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"}); err != nil {
		t.Fatalf("handleClearSecurity error = %v", err)
	}

	if !containsV4(dp.deletedV4, fwd) {
		t.Fatalf("forward key not deleted; deleted=%v", dp.deletedV4)
	}
	if !containsV4(dp.deletedV4, translatedRev) {
		t.Fatalf("translated reverse companion (val.ReverseKey) NOT deleted — leak (#2733); deleted=%v", dp.deletedV4)
	}
	if containsV4(dp.deletedV4, naiveSwap) {
		t.Fatalf("naive src/dst swap was deleted — wrong key (#2733); deleted=%v", dp.deletedV4)
	}
}

// Non-NAT no-regression: for a plain session val.ReverseKey IS the naive
// src/dst swap, so the same companion is deleted as before. Behavior
// unchanged by the fix.
func TestClearFilteredSessionsNonNATReverseUnchanged(t *testing.T) {
	fwd := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 1, 10},
		DstIP:    [4]byte{10, 0, 2, 20},
		SrcPort:  0x03e8,
		DstPort:  0x01bb,
	}
	// Non-NAT: ReverseKey == naive swap of the forward tuple.
	rev := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    fwd.DstIP,
		DstIP:    fwd.SrcIP,
		SrcPort:  fwd.DstPort,
		DstPort:  fwd.SrcPort,
	}
	val := dataplane.SessionValue{ReverseKey: rev}

	dp := &recordingClearCLIDP{
		Manager:    dataplane.New(),
		v4Sessions: map[dataplane.SessionKey]dataplane.SessionValue{fwd: val},
	}
	c := newRecordingCLI(t, dp)
	if err := c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"}); err != nil {
		t.Fatalf("handleClearSecurity error = %v", err)
	}
	if !containsV4(dp.deletedV4, fwd) {
		t.Fatalf("forward key not deleted; deleted=%v", dp.deletedV4)
	}
	if !containsV4(dp.deletedV4, rev) {
		t.Fatalf("non-NAT reverse companion not deleted; deleted=%v", dp.deletedV4)
	}
}

// A session with no reverse companion (val.ReverseKey.Protocol == 0, the
// needsReverse gate) must NOT trigger a reverse delete at all — only the
// forward entry is removed. Reverting to the naive-swap construction would
// fabricate a bogus reverse key and issue a spurious delete.
func TestClearFilteredSessionsNoReverseCompanionSkipsReverseDelete(t *testing.T) {
	fwd := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 1, 10},
		DstIP:    [4]byte{10, 0, 2, 20},
		SrcPort:  0x03e8,
		DstPort:  0x01bb,
	}
	val := dataplane.SessionValue{} // ReverseKey zero-valued -> Protocol==0

	dp := &recordingClearCLIDP{
		Manager:    dataplane.New(),
		v4Sessions: map[dataplane.SessionKey]dataplane.SessionValue{fwd: val},
	}
	c := newRecordingCLI(t, dp)
	if err := c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"}); err != nil {
		t.Fatalf("handleClearSecurity error = %v", err)
	}
	if len(dp.deletedV4) != 1 || dp.deletedV4[0] != fwd {
		t.Fatalf("expected only the forward key deleted, got %v", dp.deletedV4)
	}
}
