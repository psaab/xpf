package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// excludedPolicyStore commits a trust->untrust permit whose source-address is
// source-address-excluded (matches every source EXCEPT 10.0.99.0/24) and whose
// destination-address is destination-address-excluded (every dest EXCEPT
// 192.0.2.0/24). Exactly the #3668 negated-address case.
func excludedPolicyStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    address-book {
        global {
            address bad-src 10.0.99.0/24;
            address bad-dst 192.0.2.0/24;
        }
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy exclude-permit {
                match {
                    source-address bad-src;
                    source-address-excluded;
                    destination-address bad-dst;
                    destination-address-excluded;
                    application any;
                }
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

// TestMatchPoliciesResponseCarriesExclusionAndRuleID pins #3668 on the gRPC
// surface: a positive verdict against a source/destination-address-excluded rule
// must set source_address_excluded / destination_address_excluded and carry the
// stable rule_id inventory uses, so the answer does not read backwards and can be
// joined to the inventory / logs / tests.
//
// RED-on-revert: before #3668 MatchPoliciesResponse had no exclusion/rule_id
// fields; dropping the population in server_cluster.go (or reverting the proto)
// zeroes them and every assertion below fails.
func TestMatchPoliciesResponseCarriesExclusionAndRuleID(t *testing.T) {
	store := excludedPolicyStore(t)
	s := &Server{store: store}

	// Source OUTSIDE bad-src and destination OUTSIDE bad-dst => the excluded rule
	// matches. The printed src/dst list is the EXCLUDED set, so the flag is what
	// prevents the verdict from reading as "matched because of bad-src".
	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone:        "trust",
		ToZone:          "untrust",
		SourceIp:        "10.0.5.7",
		DestinationIp:   "198.51.100.7",
		Protocol:        "tcp",
		DestinationPort: int32Ptr17081(80),
	})
	if err != nil {
		t.Fatalf("MatchPolicies error = %v", err)
	}
	if !resp.Matched {
		t.Fatalf("expected match, got %+v", resp)
	}
	if !resp.GetSourceAddressExcluded() {
		t.Errorf("source_address_excluded = false, want true")
	}
	if !resp.GetDestinationAddressExcluded() {
		t.Errorf("destination_address_excluded = false, want true")
	}
	want := dpuserspace.StablePolicyRuleID("trust", "untrust", "exclude-permit")
	if resp.GetRuleId() != want {
		t.Errorf("rule_id = %q, want %q", resp.GetRuleId(), want)
	}
}
