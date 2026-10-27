package api

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/policymatch"
)

// hostInboundAdmitAPIStore mirrors the gRPC hostInboundAdmitStore: zone `trust`
// carries a host-inbound-traffic stanza (system-services ssh + ping, protocols
// bgp) and zone `untrust` has none (post-#3405 default-deny). No `to-zone
// junos-host` policy, so a host-bound query resolves to host-inbound and the
// #3627 B1a classifier names the admitting token.
func hostInboundAdmitAPIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust {
            host-inbound-traffic {
                system-services {
                    ssh;
                    ping;
                }
                protocols {
                    bgp;
                }
            }
        }
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// hostInboundJSON decodes the REST /security/match envelope focusing on the
// #3627 B1a structured host_inbound object.
type hostInboundJSON struct {
	Success bool `json:"success"`
	Data    struct {
		Matched              bool `json:"matched"`
		HostInboundUnmatched bool `json:"host_inbound_unmatched"`
		HostInbound          *struct {
			Status      string `json:"status"`
			Token       string `json:"token"`
			Kind        string `json:"kind"`
			Description string `json:"description"`
		} `json:"host_inbound"`
	} `json:"data"`
}

func matchHostInbound(t *testing.T, s *Server, q url.Values) hostInboundJSON {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
	s.matchPoliciesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp hostInboundJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	return resp
}

// TestMatchPoliciesRESTHostInboundToken pins #3627 B1a on the REST surface: a
// `to-zone junos-host` query returns the structured host_inbound admission
// (WHICH system-service/protocol token admits the tuple, or
// deny/global-accept), mirroring the gRPC host_inbound message and the local
// CLI line (#4352). It proves CLI/REST value-parity against the shared
// policymatch.Result.HostInbound.
//
// RED-on-revert: dropping the HostInbound assignment from the host-inbound
// branch in matchPoliciesHandler drops the JSON object and the token assertion
// fails.
func TestMatchPoliciesRESTHostInboundToken(t *testing.T) {
	store := hostInboundAdmitAPIStore(t)
	s := &Server{store: store}
	cfg := store.ActiveConfig()

	cases := []struct {
		name       string
		q          url.Values
		wantStatus string
		wantToken  string
		wantKind   string
	}{
		{
			name:       "ssh token-admit",
			q:          url.Values{"from_zone": {"trust"}, "to_zone": {"junos-host"}, "protocol": {"tcp"}, "dst_port": {"22"}, "dst_ip": {"10.0.1.10"}},
			wantStatus: "token-admit",
			wantToken:  "ssh",
			wantKind:   "system-services",
		},
		{
			name:       "bgp protocols token-admit",
			q:          url.Values{"from_zone": {"trust"}, "to_zone": {"junos-host"}, "protocol": {"tcp"}, "dst_port": {"179"}, "dst_ip": {"10.0.1.10"}},
			wantStatus: "token-admit",
			wantToken:  "bgp",
			wantKind:   "protocols",
		},
		{
			name:       "esp global-accept",
			q:          url.Values{"from_zone": {"trust"}, "to_zone": {"junos-host"}, "protocol": {"esp"}, "dst_ip": {"10.0.1.10"}},
			wantStatus: "global-accept",
		},
		{
			name:       "telnet denied",
			q:          url.Values{"from_zone": {"trust"}, "to_zone": {"junos-host"}, "protocol": {"tcp"}, "dst_port": {"23"}, "dst_ip": {"10.0.1.10"}},
			wantStatus: "denied",
		},
		{
			name:       "untrust no-stanza denied",
			q:          url.Values{"from_zone": {"untrust"}, "to_zone": {"junos-host"}, "protocol": {"tcp"}, "dst_port": {"22"}, "dst_ip": {"10.0.1.10"}},
			wantStatus: "denied",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := matchHostInbound(t, s, c.q)
			if !resp.Data.HostInboundUnmatched {
				t.Fatalf("host_inbound_unmatched = false, want true; got %+v", resp.Data)
			}
			if resp.Data.HostInbound == nil {
				t.Fatalf("host_inbound is absent (#3627 B1a regression); want status %q", c.wantStatus)
			}
			if resp.Data.HostInbound.Status != c.wantStatus {
				t.Errorf("status = %q, want %q", resp.Data.HostInbound.Status, c.wantStatus)
			}
			if resp.Data.HostInbound.Token != c.wantToken || resp.Data.HostInbound.Kind != c.wantKind {
				t.Errorf("token/kind = %q/%q, want %q/%q",
					resp.Data.HostInbound.Token, resp.Data.HostInbound.Kind, c.wantToken, c.wantKind)
			}
			if resp.Data.HostInbound.Description == "" {
				t.Errorf("description is empty; want the CLI explanation line")
			}

			// CLI/REST value-parity: the shared policymatch.Result the local CLI
			// renders must carry the identical status/token/kind/description.
			ref := policymatch.Match(cfg, restQuery(c.q))
			if ref.HostInbound == nil {
				t.Fatalf("policymatch reference HostInbound is nil")
			}
			if resp.Data.HostInbound.Status != ref.HostInbound.Status.String() ||
				resp.Data.HostInbound.Token != ref.HostInbound.Token ||
				resp.Data.HostInbound.Kind != ref.HostInbound.Kind ||
				resp.Data.HostInbound.Description != ref.HostInbound.Describe() {
				t.Errorf("REST vs CLI/SSOT drift: REST{%q/%q/%q/%q} vs ref{%q/%q/%q/%q}",
					resp.Data.HostInbound.Status, resp.Data.HostInbound.Token, resp.Data.HostInbound.Kind, resp.Data.HostInbound.Description,
					ref.HostInbound.Status.String(), ref.HostInbound.Token, ref.HostInbound.Kind, ref.HostInbound.Describe())
			}
		})
	}
}

// TestMatchPoliciesRESTHostInboundOffHostOmitted pins the presence gate: a
// transit (off-host) query has no host-inbound gate, so host_inbound is absent
// on both a positive match and a no-match/default verdict.
func TestMatchPoliciesRESTHostInboundOffHostOmitted(t *testing.T) {
	store := hostInboundAdmitAPIStore(t)
	s := &Server{store: store}

	m := matchHostInbound(t, s, url.Values{"from_zone": {"trust"}, "to_zone": {"untrust"}, "protocol": {"tcp"}, "dst_port": {"22"}})
	if !m.Data.Matched {
		t.Fatalf("matched = false, want true (trust->untrust permit)")
	}
	if m.Data.HostInbound != nil {
		t.Errorf("off-host match carries host_inbound = %+v, want absent", m.Data.HostInbound)
	}

	dd := matchHostInbound(t, s, url.Values{"from_zone": {"untrust"}, "to_zone": {"trust"}, "protocol": {"tcp"}, "dst_port": {"22"}})
	if dd.Data.HostInbound != nil {
		t.Errorf("off-host default carries host_inbound = %+v, want absent", dd.Data.HostInbound)
	}
}

// restQuery mirrors the query the REST matchPoliciesHandler builds from the URL
// selectors, so a test can recompute the shared policymatch.Result the CLI
// renders and compare fields.
func restQuery(q url.Values) policymatch.Query {
	var dstPort *uint16
	if v := q.Get("dst_port"); v != "" {
		if p, err := policymatch.ParsePort(v); err == nil {
			dstPort = p
		}
	}
	var srcPort *uint16
	if v := q.Get("source_port"); v != "" {
		if p, err := policymatch.ParsePort(v); err == nil {
			srcPort = p
		}
	}
	return policymatch.Query{
		FromZone: q.Get("from_zone"),
		ToZone:   q.Get("to_zone"),
		SrcIP:    net.ParseIP(q.Get("source_ip")),
		DstIP:    net.ParseIP(q.Get("dst_ip")),
		Protocol: q.Get("protocol"),
		SrcPort:  srcPort,
		DstPort:  dstPort,
	}
}
