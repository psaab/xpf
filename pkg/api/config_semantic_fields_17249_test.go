package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConfigHandlerIncludesSemanticFields17249(t *testing.T) {
	store := authzStore(t, `
routing-options {
    static {
        route 10.172.49.0/24 {
            next-hop 192.0.2.49;
            no-install;
            preference 5;
        }
    }
}
system {
    ntp {
        peer 192.0.2.49 {
            prefer;
        }
    }
}
security {
    address-book {
        global {
            address partner-api dns-name api.example.com ipv4-only;
        }
    }
}
`)
	server := &Server{store: store}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	server.configHandler(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/config status = %d, want %d: %s",
			response.Code, http.StatusOK, response.Body.String())
	}

	var envelope struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode GET /api/v1/config envelope: %v; body=%s", err, response.Body.String())
	}
	if !envelope.Success || len(envelope.Data) == 0 {
		t.Fatalf("GET /api/v1/config returned no config data: %s", response.Body.String())
	}
	var got struct {
		RoutingOptions struct {
			StaticRoutes []struct {
				NoInstall     bool
				Preference    int
				HasPreference bool
			} `json:"StaticRoutes"`
		} `json:"RoutingOptions"`
		System struct {
			NTPPeers       []string
			NTPPeerOptions map[string]struct {
				Prefer bool
			}
		}
		Security struct {
			AddressBook struct {
				Addresses map[string]struct {
					DNSName   string
					DNSFamily string
				}
			}
		}
	}
	if err := json.Unmarshal(envelope.Data, &got); err != nil {
		t.Fatalf("decode GET /api/v1/config data: %v; data=%s", err, envelope.Data)
	}
	if len(got.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("GET /api/v1/config StaticRoutes = %d entries, want 1: %s",
			len(got.RoutingOptions.StaticRoutes), envelope.Data)
	}
	route := got.RoutingOptions.StaticRoutes[0]
	if !route.NoInstall || route.Preference != 5 || !route.HasPreference {
		t.Errorf("GET /api/v1/config route semantic fields = %+v, want NoInstall=true, Preference=5, HasPreference=true",
			route)
	}
	if len(got.System.NTPPeers) != 1 || got.System.NTPPeers[0] != "192.0.2.49" {
		t.Errorf("GET /api/v1/config NTPPeers = %v, want [192.0.2.49]", got.System.NTPPeers)
	}
	if option := got.System.NTPPeerOptions["192.0.2.49"]; !option.Prefer {
		t.Errorf("GET /api/v1/config NTPPeerOptions[192.0.2.49] = %+v, want Prefer=true",
			option)
	}
	dnsAddress := got.Security.AddressBook.Addresses["partner-api"]
	if dnsAddress.DNSName != "api.example.com" || dnsAddress.DNSFamily != "ipv4-only" {
		t.Errorf("GET /api/v1/config DNS fields = %+v, want api.example.com/ipv4-only",
			dnsAddress)
	}
}
