package networkd

import (
	"os"
	"testing"
)

// #16791: Apply's activation tail now consults linkExists (over
// net.InterfaceByName) to skip managed rows that name no live netdev.
// The unit sandbox guarantees only the loopback, so tests whose fixtures
// use production-style names (trust0, dmz0, wan0, ...) would otherwise see
// those names as "absent" and never exercise the normal reconfigure path
// their argv/count assertions were written against. Default linkExists in
// tests to "present" so every pre-existing tail test keeps exercising the
// path it always did; the #16791 tests override it per-test to model
// absent (and, via stubLinkExists16791, present) links explicitly.
func TestMain(m *testing.M) {
	prodLinkExists := linkExists
	linkExists = func(string) (bool, error) { return true, nil }
	// #18597: the tail queries networkd for failed links; the sandbox has no
	// networkd, and a failed query falls back to the full pass. Default to
	// "nothing failed" so tail tests exercise the narrowed set they assert;
	// keep_master_18597_test.go covers both the failed-link and the
	// query-error arms explicitly.
	prodFailedLinks := networkdFailedLinks
	networkdFailedLinks = func() (map[string]bool, error) { return map[string]bool{}, nil }
	code := m.Run()
	networkdFailedLinks = prodFailedLinks
	linkExists = prodLinkExists
	os.Exit(code)
}
