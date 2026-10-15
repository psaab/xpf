package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// #13203 / D10-07: verify-dataplane, protocol-versions and version silently
// ignored extra positional args, and `upgrade kernel` dropped --unit on
// promote while advertising an arm flag order Go cannot parse.

func TestParseNoOperandArgsRejectsExtras_13203(t *testing.T) {
	if err := parseNoOperandArgs("verify-dataplane", nil); err != nil {
		t.Fatalf("empty: %v", err)
	}
	if err := parseNoOperandArgs("verify-dataplane", []string{"/tmp/bad.o"}); err == nil {
		t.Fatal("verify-dataplane accepted a candidate path it would silently ignore")
	}
	if err := parseNoOperandArgs("version", []string{"extra"}); err == nil {
		t.Fatal("version accepted an extra operand")
	}
	if err := parseNoOperandArgs("protocol-versions", []string{"extra"}); err == nil {
		t.Fatal("protocol-versions accepted an extra operand")
	}
}

func TestParseProtocolVersionsOutput_13203(t *testing.T) {
	var b strings.Builder
	if err := writeProtocolVersions(&b, "version", "1.2.3"); err != nil {
		t.Fatalf("valid form: %v", err)
	}
	if !strings.Contains(b.String(), "xpf-version=1.2.3\n") {
		t.Fatalf("output missing version:\n%s", b.String())
	}
	var b2 strings.Builder
	if err := writeProtocolVersions(&b2, "protocol-versions", "1.2.3", "extra"); err == nil {
		t.Fatal("protocol-versions output accepted extra operand")
	}
	if b2.Len() != 0 {
		t.Fatalf("rejected invocation produced output %q", b2.String())
	}
}

func TestParseVerifyDataplaneArgs_13203(t *testing.T) {
	if err := parseVerifyDataplaneArgs(nil); err != nil {
		t.Fatalf("empty: %v", err)
	}
	if err := parseVerifyDataplaneArgs([]string{"/tmp/bad.o"}); err == nil {
		t.Fatal("verify-dataplane accepted positional candidate path")
	}
}

func TestKernelUsageFlagsBeforeVersion_13203(t *testing.T) {
	if err := validateKernelVerbArgs("arm", []string{"6.18.1"}); err != nil {
		t.Fatalf("valid arm operand: %v", err)
	}
	if err := validateKernelVerbArgs("arm", []string{"6.18.1", "-strict-watchdog"}); err == nil {
		t.Fatal("arm accepted extra positional left behind by flag.Parse")
	}
	if got := kernelUsage; !strings.Contains(got, "arm [flags] <version>") || !strings.Contains(got, "promote [flags]") {
		t.Fatalf("kernelUsage advertises unparsable order: %q", got)
	}
}

func TestNewKernelConfigUsesUnit_13203(t *testing.T) {
	var gotUnit string
	restore := swapUnitActive(func(_ context.Context, unit string) (bool, error) {
		gotUnit = unit
		return true, nil
	})
	defer restore()
	restoreStatus := swapHelperStatus(func(string, time.Duration) (bool, bool, int, error) {
		return true, true, 1, nil
	})
	defer restoreStatus()
	restoreSock := swapControlSock(func(string) string { return "/unused.sock" })
	defer restoreSock()

	cfg := newKernelConfig("/unused-journal", false, time.Second, "xpfd-custom")
	if cfg.Sys == nil {
		t.Fatal("newKernelConfig did not wire Sys")
	}
	if _, err := cfg.Sys.ForwardBeacon(10 * time.Millisecond); err != nil {
		t.Fatalf("ForwardBeacon: %v", err)
	}
	if gotUnit != "xpfd-custom" {
		t.Fatalf("ForwardBeacon queried unit %q, want --unit value %q (dropped --unit)", gotUnit, "xpfd-custom")
	}
}
