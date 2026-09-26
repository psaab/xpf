package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

type extensiveCounterTestDP struct {
	*dataplane.Manager
	counters dataplane.InterfaceCounterValue
	readErr  error
}

func (d *extensiveCounterTestDP) IsLoaded() bool { return true }

func (d *extensiveCounterTestDP) ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error) {
	return d.counters, d.readErr
}

func TestShowInterfacesExtensiveDuplexUnknown10843(t *testing.T) {
	if got := formatDuplex(readLinkDuplex("xpf-no-such-interface-10843")); got != "Unknown" {
		t.Fatalf("missing sysfs duplex rendered %q, want Unknown", got)
	}
	if got := formatDuplex("unknown"); got != "Unknown" {
		t.Fatalf("unknown sysfs duplex rendered %q, want Unknown", got)
	}
	if got := formatDuplex("unsupported"); got != "Unknown" {
		t.Fatalf("unsupported sysfs duplex rendered %q, want Unknown", got)
	}
	if got := formatDuplex("full"); got != "Full-duplex" {
		t.Fatalf("full sysfs duplex rendered %q, want Full-duplex", got)
	}
	if got := formatDuplex("half"); got != "Half-duplex" {
		t.Fatalf("half sysfs duplex rendered %q, want Half-duplex", got)
	}
}

func TestShowInterfacesExtensiveReportsCounterReadError10843(t *testing.T) {
	c, iface, _ := identityShowCLI(t)
	c.dp = &extensiveCounterTestDP{
		Manager: dataplane.New(),
		readErr: errors.New("injected counter read failure"),
	}

	out := captureStdout(t, func() {
		if err := c.showInterfacesExtensiveFiltered(iface); err != nil {
			t.Fatalf("showInterfacesExtensiveFiltered(%q): %v", iface, err)
		}
	})
	if !strings.Contains(out, "warning: BPF interface counter read failed for "+iface+": injected counter read failure") {
		t.Fatalf("counter read failure missing from output:\n%s", out)
	}
}

func TestShowInterfacesExtensiveReportsZeroCounters10843(t *testing.T) {
	c, iface, _ := identityShowCLI(t)
	c.dp = &extensiveCounterTestDP{Manager: dataplane.New()}

	out := captureStdout(t, func() {
		if err := c.showInterfacesExtensiveFiltered(iface); err != nil {
			t.Fatalf("showInterfacesExtensiveFiltered(%q): %v", iface, err)
		}
	})
	for _, want := range []string{
		"BPF statistics:",
		"Input:  0 packets, 0 bytes",
		"Output: 0 packets, 0 bytes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("zero-valued BPF counter output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Interface "+iface+" not found") {
		t.Fatalf("matched interface was reported not found:\n%s", out)
	}
}

func TestShowInterfacesExtensiveAddressReadErrorNote10843(t *testing.T) {
	out := captureStdout(t, func() {
		printExtensiveAddresses(nil, errors.New("injected address read failure"), 1500)
	})
	if !strings.Contains(out, "Addresses unavailable: injected address read failure") {
		t.Fatalf("address read failure missing from output: %q", out)
	}
}

func TestShowInterfacesExtensiveEmptyFilterNotFound10843(t *testing.T) {
	c, _, _ := identityShowCLI(t)
	const missing = "xpf-no-such-interface-10843"
	out := captureStdout(t, func() {
		if err := c.showInterfacesExtensiveFiltered(missing); err != nil {
			t.Fatalf("showInterfacesExtensiveFiltered(%q): %v", missing, err)
		}
	})
	if !strings.Contains(out, "Interface "+missing+" not found") {
		t.Fatalf("empty filter result missing interface-not-found output:\n%s", out)
	}
}
