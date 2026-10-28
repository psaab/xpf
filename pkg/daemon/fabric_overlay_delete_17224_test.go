package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// #17224: fabric IPVLAN deletes must go through the fabricLinkDel seam and
// must not log "removed" when the delete fails; the apply stale sweep must
// enumerate via fabricOverlayNames().

func captureSlog17224(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestApplyStaleSweepDeleteFailureLogsErrorNotRemoved17224 is the acceptance
// cell from the issue: a fabricLinkDel error injected into the apply stale
// sweep surfaces as an Error and no "removed stale fabric IPVLAN" Info.
func TestApplyStaleSweepDeleteFailureLogsErrorNotRemoved17224(t *testing.T) {
	logs := captureSlog17224(t)
	boom := errors.New("delete refused")
	d := &Daemon{linkByNameFn: func(name string) (netlink.Link, error) {
		if name == "fab0" {
			return ipvlan8372(name), nil
		}
		return nil, netlink.LinkNotFoundError{}
	}, linkDelFn: func(netlink.Link) error { return boom }}
	// Config names no fabric interface, so fab0 is stale and swept.
	cfg := &config.Config{Interfaces: config.InterfacesConfig{
		Interfaces: map[string]*config.InterfaceConfig{}}}

	if err := d.applyFabricIPVLAN(cfg); err != nil {
		t.Fatalf("applyFabricIPVLAN: %v", err)
	}
	out := logs.String()
	if !strings.Contains(out, "level=ERROR") ||
		!strings.Contains(out, "fabric IPVLAN delete failed") ||
		!strings.Contains(out, `reason="stale fabric IPVLAN"`) {
		t.Errorf("failing delete must log Error through the helper; got:\n%s", out)
	}
	if strings.Contains(out, "removed stale fabric IPVLAN") ||
		(strings.Contains(out, "level=INFO") && strings.Contains(out, "removed fabric IPVLAN")) {
		t.Errorf("failed delete logged as removed:\n%s", out)
	}
}

// TestApplyStaleSweepDeleteSuccessLogsRemoved17224 is the control: a
// successful sweep delete logs the Info exactly once, through the helper.
func TestApplyStaleSweepDeleteSuccessLogsRemoved17224(t *testing.T) {
	logs := captureSlog17224(t)
	var deleted []string
	d := &Daemon{linkByNameFn: func(name string) (netlink.Link, error) {
		if name == "fab0" {
			return ipvlan8372(name), nil
		}
		return nil, netlink.LinkNotFoundError{}
	}, linkDelFn: func(l netlink.Link) error {
		deleted = append(deleted, l.Attrs().Name)
		return nil
	}}
	cfg := &config.Config{Interfaces: config.InterfacesConfig{
		Interfaces: map[string]*config.InterfaceConfig{}}}

	if err := d.applyFabricIPVLAN(cfg); err != nil {
		t.Fatalf("applyFabricIPVLAN: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "fab0" {
		t.Fatalf("sweep must delete stale fab0 exactly once; deleted=%v", deleted)
	}
	out := logs.String()
	if !strings.Contains(out, "removed fabric IPVLAN") ||
		!strings.Contains(out, `reason="stale fabric IPVLAN"`) {
		t.Errorf("successful delete must log Info via helper; got:\n%s", out)
	}
	if strings.Contains(out, "level=ERROR") {
		t.Errorf("successful delete must not log Error:\n%s", out)
	}
}

// TestDeleteFabricOverlayHelper17224 pins the helper contract directly:
// failure returns the error and logs Error only; success logs Info only.
func TestDeleteFabricOverlayHelper17224(t *testing.T) {
	logs := captureSlog17224(t)
	boom := errors.New("nope")
	d := &Daemon{linkDelFn: func(netlink.Link) error { return boom }}
	if err := d.deleteFabricOverlay(ipvlan8372("fab1"), "unit reason"); !errors.Is(err, boom) {
		t.Fatalf("helper must return the delete error, got %v", err)
	}
	if out := logs.String(); !strings.Contains(out, "fabric IPVLAN delete failed") ||
		!strings.Contains(out, `reason="unit reason"`) ||
		strings.Contains(out, "removed fabric IPVLAN") {
		t.Errorf("failure must log Error only; got:\n%s", out)
	}

	logs.Reset()
	d.linkDelFn = func(netlink.Link) error { return nil }
	if err := d.deleteFabricOverlay(ipvlan8372("fab1"), "unit reason"); err != nil {
		t.Fatalf("helper success: %v", err)
	}
	if out := logs.String(); !strings.Contains(out, "removed fabric IPVLAN") ||
		strings.Contains(out, "level=ERROR") {
		t.Errorf("success must log Info only; got:\n%s", out)
	}
}

// TestApplyStaleSweepEnumeratesSingleSource17224 proves the sweep iterates
// fabricOverlayNames(): every name it returns is looked up, so a future
// third overlay would be swept. The hardcoded {"fab0","fab1"} copy would
// also pass for two names; pinning via lookup count per name catches a
// regression that re-hardcodes a subset.
func TestApplyStaleSweepEnumeratesSingleSource17224(t *testing.T) {
	captureSlog17224(t)
	looked := map[string]int{}
	d := &Daemon{linkByNameFn: func(name string) (netlink.Link, error) {
		looked[name]++
		return nil, netlink.LinkNotFoundError{}
	}, linkDelFn: func(netlink.Link) error { return nil }}
	cfg := &config.Config{Interfaces: config.InterfacesConfig{
		Interfaces: map[string]*config.InterfaceConfig{}}}
	if err := d.applyFabricIPVLAN(cfg); err != nil {
		t.Fatalf("applyFabricIPVLAN: %v", err)
	}
	for _, n := range fabricOverlayNames() {
		if looked[n] == 0 {
			t.Errorf("sweep never looked up %q from fabricOverlayNames()", n)
		}
	}
}
