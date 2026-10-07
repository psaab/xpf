package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

type recordingRouteLister12077 struct {
	fakeRouteLister
	calls int
}

func (f *recordingRouteLister12077) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	f.calls++
	return f.fakeRouteLister.RouteList(link, family)
}

func (f *recordingRouteLister12077) RouteListFilteredIter(family int, filter *netlink.Route, flags uint64, fn func(netlink.Route) bool) error {
	f.calls++
	return f.fakeRouteLister.RouteListFilteredIter(family, filter, flags, fn)
}

func (f *recordingRouteLister12077) RouteListFiltered(family int, filter *netlink.Route, flags uint64) ([]netlink.Route, error) {
	f.calls++
	return f.fakeRouteLister.RouteListFiltered(family, filter, flags)
}

func (f *recordingRouteLister12077) LinkByName(name string) (netlink.Link, error) {
	f.calls++
	return f.fakeRouteLister.LinkByName(name)
}

func (f *recordingRouteLister12077) LinkByIndex(index int) (netlink.Link, error) {
	f.calls++
	return f.fakeRouteLister.LinkByIndex(index)
}

func TestTestRoutingRejectsMalformedSelectors12077(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"misspelled instance", []string{"destination", "10.1.2.3", "instnace", "dmz"}, "unknown selector \"instnace\""},
		{"unknown selector", []string{"destination", "10.1.2.3", "bogus"}, "unknown selector \"bogus\" (want \"destination <ip-or-prefix> [instance <name>]\")"},
		{"missing instance value", []string{"destination", "10.1.2.3", "instance"}, "selector \"instance\" requires a value"},
		{"missing destination value", []string{"destination"}, "selector \"destination\" requires a value"},
		{"empty instance value", []string{"destination", "10.1.2.3", "instance", ""}, "selector \"instance\" requires a value"},
		{"empty destination value", []string{"destination", ""}, "selector \"destination\" requires a value"},
		{"whitespace-only destination value", []string{"destination", " \t "}, "selector \"destination\" requires a value"},
		{"whitespace-only instance value", []string{"destination", "10.1.2.3", "instance", "  "}, "selector \"instance\" requires a value"},
		{"repeated destination", []string{"destination", "10.1.2.3", "destination", "10.9.9.9"}, "duplicate selector \"destination\""},
		{"repeated instance", []string{"destination", "10.1.2.3", "instance", "a", "instance", "b"}, "duplicate selector \"instance\""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lister := &recordingRouteLister12077{
				fakeRouteLister: fakeRouteLister{v4: stdV4Routes()},
			}
			c := &CLI{routing: routing.NewManagerWithRouteListerForTest(lister)}
			var err error
			out := captureStdout(t, func() {
				err = c.testRouting(tc.args)
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("testRouting(%v) error = %v, want diagnostic containing %q", tc.args, err, tc.want)
			}
			if lister.calls != 0 {
				t.Fatalf("testRouting(%v) made %d route-manager calls before rejecting input", tc.args, lister.calls)
			}
			if strings.Contains(out, "Routing lookup") {
				t.Fatalf("testRouting(%v) printed lookup output before rejecting input: %q", tc.args, out)
			}
		})
	}
}
