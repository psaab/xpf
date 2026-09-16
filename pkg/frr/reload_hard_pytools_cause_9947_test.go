package frr

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// #9947 item (8): when BOTH reload legs fail, the hard error must preserve
// the PRIMARY cause alongside the fallback's. Dropping perr hides a
// pytools-missing primary behind the vtysh error: IsFRRReloadPyMissing goes
// false, the retry takes the fast rungs despite a missing script that fast
// retries cannot fix, and the daemon's persistent-cause message never fires.
func TestReloadHardFailurePreservesPytoolsCause9947(t *testing.T) {
	primaryErr := os.ErrNotExist
	fake := &fakeExecutor{
		frrReloadPyErr: primaryErr,
		vtyshLoadResp:  []byte("syntax error at line 12"),
		vtyshLoadErr:   errors.New("exit status 1"),
	}
	m := &Manager{exec: fake, frrConf: "/tmp/test-frr.conf"}
	err := m.reloadForTest()
	if err == nil {
		t.Fatal("reload: expected hard error, got nil")
	}
	if errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("hard double-failure must not be reported as degraded: %v", err)
	}
	if !errors.Is(err, primaryErr) {
		t.Fatalf("hard error dropped the primary cause: %v", err)
	}
	if !IsFRRReloadPyMissing(err) {
		t.Fatalf("hard+pytools-missing error must classify as pytools-missing (slow retry): %v", err)
	}
	if !strings.Contains(err.Error(), "syntax error at line 12") {
		t.Errorf("reload error %q missing captured fallback output", err.Error())
	}
}
