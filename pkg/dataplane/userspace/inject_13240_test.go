package userspace

import (
	"strings"
	"syscall"
	"testing"
)

// #13240 (D5-14): BuildInjectPacketRequest must produce a request the
// helper seam accepts without emit-on-wire, and DecodeInjectPacketTarget
// must never return a nil map with a nil error.
func TestBuildInjectNonEmitOnWireFamilyAndNullTarget13240(t *testing.T) {
	if _, err := BuildInjectPacketRequest(999999, "valid", map[string]string{
		"destination-ip": "2001:db8::1",
	}, ProcessStatus{}); err == nil {
		t.Fatal("BuildInjectPacketRequest(slot=999999, non-emit) succeeded, want slot out-of-range")
	}

	v6, err := BuildInjectPacketRequest(7, "valid", map[string]string{
		"destination-ip": "2001:db8::1",
	}, ProcessStatus{})
	if err != nil {
		t.Fatalf("BuildInjectPacketRequest IPv6 non-emit: %v", err)
	}
	if v6.AddrFamily != uint8(syscall.AF_INET6) {
		t.Fatalf("IPv6 non-emit AddrFamily=%d, want AF_INET6(%d)", v6.AddrFamily, syscall.AF_INET6)
	}
	if err := validateInjectPacketRequestForHelper(v6, ProcessStatus{}); err != nil {
		t.Fatalf("built IPv6 request rejected by helper seam: %v", err)
	}

	v4, err := BuildInjectPacketRequest(7, "valid", map[string]string{
		"destination-ip": "192.0.2.1",
	}, ProcessStatus{})
	if err != nil {
		t.Fatalf("BuildInjectPacketRequest IPv4 non-emit: %v", err)
	}
	if v4.AddrFamily != uint8(syscall.AF_INET) {
		t.Fatalf("IPv4 non-emit AddrFamily=%d, want AF_INET", v4.AddrFamily)
	}

	if _, err := BuildInjectPacketRequest(7, "valid", map[string]string{
		"destination-ip": "not-an-ip",
	}, ProcessStatus{}); err == nil {
		t.Fatal("BuildInjectPacketRequest accepted invalid destination-ip without emit-on-wire")
	}

	// Fault mode intentionally carries zeroed family/protocol; must not
	// be "normalized" into a seemingly-valid request.
	fault, err := BuildInjectPacketRequest(7, "metadata-parse-error", map[string]string{
		"destination-ip": "2001:db8::1",
	}, ProcessStatus{})
	if err != nil {
		t.Fatalf("metadata-parse-error build: %v", err)
	}
	if fault.AddrFamily != 0 || fault.Protocol != 0 || fault.MetadataValid {
		t.Fatalf("metadata-parse-error fault mutated: %+v", fault)
	}

	extra, err := DecodeInjectPacketTarget("xpf-inject-extra:null")
	if err == nil || !strings.Contains(err.Error(), "invalid userspace inject target extras") {
		t.Fatalf("DecodeInjectPacketTarget(null) err=%v extra=%v, want extras error", err, extra)
	}
	if extra != nil {
		t.Fatalf("DecodeInjectPacketTarget(null) extra=%v, want nil on error", extra)
	}
}
