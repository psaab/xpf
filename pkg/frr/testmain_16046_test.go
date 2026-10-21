// testmain_16046_test.go — #16046 fold-2: the suite's default frr-group
// resolution. planFRRWrite fails closed when an existing wider-than-0640
// frr.conf meets an frr group it cannot name AND install (publishing
// would be either world-readable or service-unreadable). Most suite
// fixtures seed 0644 temp files without caring about modes; running
// them under the host resolver would make every such write depend on
// root + a host frr group. TestMain therefore installs a deterministic
// default — the test process's own egid as the service gid — so seeded
// files are already service-group files and tightening is pure
// preserve (no chown, no root needed). Tests that exercise resolution
// itself stub resolveFRRGroup explicitly and restore it.
//
// Limitation (deliberate): fresh-create owner pinning to (0, gid) only
// engages when the gid is chown-installable by this process; in unit
// tests the temp file already carries the process (uid, egid), so the
// fresh owner arm lands process-owned rather than uid 0. The production
// fresh owner (0, frr-gid) is pinned at plan level by
// TestFRRWritePlanDecision under a root-only stub.
package frr

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	resolveFRRGroup = func() (int, bool) { return os.Getegid(), true }
	os.Exit(m.Run())
}
