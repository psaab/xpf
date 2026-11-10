package cluster

import "path/filepath"

// SetStateDirForTesting redirects every durable state file this package keeps
// under /var/lib/xpf into dir and returns a restore function (#19084). It is
// for OTHER packages' tests, which cannot reach the unexported path vars: a
// pkg/daemon test that builds a Manager and starts cluster comms persists the
// boot epoch, the peer-epoch record (and its .lock), the fabric-auth grace
// anchor and the unkeyed-authority grace anchor. Run as real root, those
// writes landed in the host's /var/lib/xpf. Test-only; not for production
// callers. TestStateDirForTestingCoversEveryStatePath19084 fails when a new
// /var/lib/xpf path is added here without being listed below.
func SetStateDirForTesting(dir string) func() {
	paths := []*string{&bootEpochPath, &peerEpochStatePath, &fabricAuthGraceStatePath, &unkeyedAuthorityGraceStatePath}
	orig := make([]string, len(paths))
	for i, p := range paths {
		orig[i] = *p
		*p = filepath.Join(dir, filepath.Base(*p))
	}
	return func() {
		for i, p := range paths {
			*p = orig[i]
		}
	}
}
