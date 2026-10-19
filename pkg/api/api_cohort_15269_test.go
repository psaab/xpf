package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #15269 C09-01 REST + C09-03 applications.

func TestRESTDNATSourceMatch15269(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set security zones security-zone untrust",
		"set security nat destination pool dp1 address 10.0.0.5",
		"set security nat destination rule-set drs from zone untrust",
		"set security nat destination rule-set drs rule scoped match source-address 198.51.100.0/24",
		"set security nat destination rule-set drs rule scoped match destination-address 203.0.113.10/32",
		"set security nat destination rule-set drs rule scoped then destination-nat pool dp1",
		"set security nat destination rule-set drs rule open match destination-address 203.0.113.11/32",
		"set security nat destination rule-set drs rule open then destination-nat pool dp1",
	})
	rec := httptest.NewRecorder()
	s.natDestHandler(rec, httptest.NewRequest(http.MethodGet, "/nat/destination", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Data []NATDestInfo `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byName := map[string]NATDestInfo{}
	for _, i := range env.Data {
		byName[i.Name] = i
	}
	if got := byName["scoped"].SourceMatch; got != "198.51.100.0/24" {
		t.Errorf("scoped source_match=%q", got)
	}
	if got := byName["open"].SourceMatch; got != "0.0.0.0/0" {
		t.Errorf("open source_match=%q", got)
	}
}

func TestRESTApplicationsSuffix15269(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set applications application pingx protocol icmp",
		"set applications application pingx icmp-type 8",
		"set applications application pingx icmp-code 0",
		"set applications application pingx source-port 1024-65535",
		"set applications application tcpx protocol tcp",
		"set applications application tcpx destination-port 80",
		"set applications application tcpx source-port 1024-65535",
	})
	out := renderShowTextBody(t, s, "applications")
	if !strings.Contains(out, "icmp-type=8") || !strings.Contains(out, "icmp-code=0") {
		t.Errorf("missing icmp type/code:\n%s", out)
	}
	if !strings.Contains(out, "src-port=1024-65535") {
		t.Errorf("missing src-port:\n%s", out)
	}
	// rows differ: icmp row carries icmp-*, tcp row does not
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "pingx") && !strings.Contains(line, "icmp-type=8") {
			t.Errorf("pingx row wrong: %q", line)
		}
		if strings.Contains(line, "tcpx") && strings.Contains(line, "icmp-type") {
			t.Errorf("tcpx row must not carry icmp: %q", line)
		}
	}
}
