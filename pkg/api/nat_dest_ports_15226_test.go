package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/natshow"
)

// nat_dest_ports_15226_test.go — #15226 (A42-02).
//
// REST natDestHandler copied only the singular DestinationPort into
// dst_port, so a multi-port or port-range DNAT rule was understated as its
// first port while the dataplane enforces the full list. The handler now
// also carries dst_ports from the shared natshow computation.
//
// RED-on-revert: restore the singular read and dst_ports is empty.

func TestRESTNATDestCarriesAllPorts15226(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat destination pool dp1 address 10.0.0.5",
		"set security nat destination rule-set drs from zone untrust",
		"set security nat destination rule-set drs rule dr-multi match destination-address 203.0.113.10/32",
		"set security nat destination rule-set drs rule dr-multi match destination-port [ 80 443 ]",
		"set security nat destination rule-set drs rule dr-multi then destination-nat pool dp1",
		"set security nat destination rule-set drs rule dr-range match destination-address 203.0.113.11/32",
		"set security nat destination rule-set drs rule dr-range match destination-port 20000 to 20003",
		"set security nat destination rule-set drs rule dr-range then destination-nat pool dp1",
		"set security nat destination rule-set drs rule dr-none match destination-address 203.0.113.12/32",
		"set security nat destination rule-set drs rule dr-none then destination-nat pool dp1",
	}
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	s := NewServer(Config{Addr: "127.0.0.1:0", Store: store})

	rec := httptest.NewRecorder()
	s.natDestHandler(rec, httptest.NewRequest(http.MethodGet, "/nat/destination", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("natDest status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var env struct {
		Data []NATDestInfo `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	byName := map[string]NATDestInfo{}
	for _, info := range env.Data {
		byName[info.Name] = info
	}

	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("PREMISE: committed config must be active")
	}
	for _, tc := range []struct {
		name string
		want []uint32
	}{
		{"dr-multi", []uint32{80, 443}},
		{"dr-range", []uint32{20000, 20001, 20002, 20003}},
		{"dr-none", nil},
	} {
		info, ok := byName[tc.name]
		if !ok {
			t.Errorf("rule %q missing from REST destination view", tc.name)
			continue
		}
		if len(info.DstPorts) != len(tc.want) {
			t.Errorf("#15226: %s dst_ports = %v, want %v", tc.name, info.DstPorts, tc.want)
			continue
		}
		for i := range info.DstPorts {
			if info.DstPorts[i] != tc.want[i] {
				t.Errorf("#15226: %s dst_ports = %v, want %v", tc.name, info.DstPorts, tc.want)
				break
			}
		}
		var wantFirst uint16
		if len(tc.want) > 0 {
			wantFirst = uint16(tc.want[0])
		}
		if info.DstPort != wantFirst {
			t.Errorf("control: %s dst_port = %d, want first port %d", tc.name, info.DstPort, wantFirst)
		}
	}
	// Agreement with the shared computation for the multi-port rule.
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		for _, rule := range rs.Rules {
			if rule.Name != "dr-multi" {
				continue
			}
			if ports := natshow.RuleMatchDestPorts(rule); len(ports) != len(byName["dr-multi"].DstPorts) {
				t.Errorf("#15226: REST dst_ports disagrees with natshow.RuleMatchDestPorts (%v)", ports)
			}
		}
	}
}
