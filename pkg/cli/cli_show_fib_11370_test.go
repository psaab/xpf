package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type fibDumpCLIDP11370 struct {
	*dataplane.Manager
	calls      int
	generation uint32
	routes     []dpuserspace.FibRouteWire
	err        error
}

func (d *fibDumpCLIDP11370) DumpFIB() (uint32, []dpuserspace.FibRouteWire, error) {
	d.calls++
	return d.generation, d.routes, d.err
}

func TestShowRouteFibDumpReadsHelper11370(t *testing.T) {
	dp := &fibDumpCLIDP11370{
		Manager:    dataplane.New(),
		generation: 9,
		routes: []dpuserspace.FibRouteWire{{
			Table:       "blue.inet.0",
			Family:      "inet",
			Destination: "203.0.113.0/24",
			Kind:        "route",
			NextHops: []dpuserspace.FibNextHopWire{{
				NextHop:   "192.0.2.1",
				Ifindex:   7,
				Interface: "ge-0/0/0",
				Weight:    2,
			}},
			Preference: 17,
			MTU:        1400,
		}},
	}
	c := &CLI{dp: dp}
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleShowRoute([]string{"fib"})
	})
	if callErr != nil {
		t.Fatalf("show route fib: %v", callErr)
	}
	if dp.calls != 1 {
		t.Fatalf("DumpFIB calls = %d, want exactly one helper read", dp.calls)
	}
	for _, want := range []string{
		"Fast-path FIB (generation 9)",
		"blue.inet.0",
		"203.0.113.0/24",
		"192.0.2.1 via ge-0/0/0 weight 2",
		"17",
		"1400",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("show route fib output lacks %q: %q", want, out)
		}
	}
}
