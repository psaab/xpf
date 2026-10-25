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
	code := m.Run()
	linkExists = prodLinkExists
	os.Exit(code)
}
