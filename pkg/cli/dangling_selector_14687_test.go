package cli

import (
	"strings"
	"testing"
)

// #14687 handler half: a dangling selector must error instead of widening
// to the full listing. Canonicalize already refuses these lines for a
// restricted class; an unrestricted class reaches the dispatcher, which
// must not silently serve the broader command either.
//
// RED on base: handleShowScreen(["ids-option"]) returned showScreen()
// (all profiles) with nil error, and handleShow firewall with a dangling
// `filter` returned showFirewallFilters() with nil error.
func TestDanglingScreenIdsOptionErrors14687(t *testing.T) {
	c := maximalScreenCLIStore(t)
	var err error
	out := captureStdout(t, func() {
		err = c.handleShowScreen([]string{"ids-option"})
	})
	if err == nil {
		t.Fatalf("handleShowScreen(ids-option) must error on a dangling selector, got nil; output:\n%s", out)
	}
	if !strings.Contains(err.Error(), "ids-option") {
		t.Fatalf("error must name the dangling selector, got: %v", err)
	}
	if strings.Contains(out, "maxp") {
		t.Errorf("dangling ids-option must not dump profiles, got:\n%s", out)
	}
}

func TestDanglingFirewallFilterErrors14687(t *testing.T) {
	store := filterDSCPSyncStore(t)
	c := &CLI{store: store}
	err := c.handleShow([]string{"firewall", "filter"})
	if err == nil {
		t.Fatalf("handleShow(firewall filter) must error on a dangling selector, got nil (pre-fix lists all filters)")
	}
	if !strings.Contains(err.Error(), "filter") {
		t.Fatalf("error must name the dangling selector, got: %v", err)
	}
}

func TestDanglingScreenStatisticsZoneErrors14687(t *testing.T) {
	c := maximalScreenCLIStore(t)
	err := c.handleShowScreen([]string{"statistics", "zone"})
	if err == nil {
		t.Fatalf("handleShowScreen(statistics zone) must error on a dangling selector, got nil (pre-fix dumps all zones)")
	}
}

// Controls: the complete forms still render.
func TestCompleteScreenAndFirewallFormsStillRender14687(t *testing.T) {
	c := maximalScreenCLIStore(t)
	out := captureStdout(t, func() {
		if err := c.handleShowScreen([]string{"ids-option", "maxp"}); err != nil {
			t.Fatalf("handleShowScreen(ids-option maxp): %v", err)
		}
	})
	if !strings.Contains(out, "TCP land") {
		t.Errorf("complete ids-option form must render the profile, got:\n%s", out)
	}
	store := filterDSCPSyncStore(t)
	c2 := &CLI{store: store}
	out2 := captureStdout(t, func() {
		if err := c2.handleShow([]string{"firewall", "filter", "mark"}); err != nil {
			t.Fatalf("handleShow(firewall filter mark): %v", err)
		}
	})
	if out2 == "" {
		t.Errorf("complete filter form must render output")
	}
	out3 := captureStdout(t, func() {
		if err := c.handleShowScreen(nil); err != nil {
			t.Fatalf("handleShowScreen(nil): %v", err)
		}
	})
	if out3 == "" {
		t.Errorf("bare screen form must render output")
	}
}
