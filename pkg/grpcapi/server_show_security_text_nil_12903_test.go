package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/feeds"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// renderNoPanic runs a ShowText render body and converts a panic into a hard
// test failure. The #12903 defect class is a present-but-nil pointer-valued
// map entry (admitted by the tolerant-load / peer-sync path, #1960) reaching
// a display handler that dereferenced it without a guard — the handler must
// fail closed by skipping the slot, never by panicking the RPC.
func renderNoPanic(t *testing.T, render func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handler panicked on a present-but-nil map value (must skip the slot, not panic): %v", r)
		}
	}()
	render()
}

func icmpPtr(v uint8) *uint8 { return &v }

// TestShowSecurityTextNilMapValuesNoPanic12903 is the #12903 RED-on-revert
// proof: one nil value in each distinct pointer-valued map the five gRPC
// show-security text handlers range over. On master every marked row
// dereferenced the nil slot and panicked; the fix skips the slot and still
// renders the real sibling.
func TestShowSecurityTextNilMapValuesNoPanic12903(t *testing.T) {
	t.Run("schedulers", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Schedulers = map[string]*config.SchedulerConfig{
			"real-sched": {Name: "real-sched", StartTime: "09:00"},
			"nil-sched":  nil,
		}
		var buf strings.Builder
		renderNoPanic(t, func() { (&Server{}).showSchedulers(cfg, &buf) })
		out := buf.String()
		if !strings.Contains(out, "Scheduler: real-sched") {
			t.Fatalf("real scheduler missing from output:\n%s", out)
		}
		if strings.Contains(out, "nil-sched") {
			t.Fatalf("nil scheduler slot rendered:\n%s", out)
		}
	})

	t.Run("applications", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Applications.Applications = map[string]*config.Application{
			"real-app": {Name: "real-app", Protocol: "tcp"},
			"nil-app":  nil,
		}
		var buf strings.Builder
		renderNoPanic(t, func() { (&Server{}).showApplications(cfg, &buf) })
		out := buf.String()
		if !strings.Contains(out, "real-app") {
			t.Fatalf("real application missing from output:\n%s", out)
		}
		if strings.Contains(out, "nil-app") {
			t.Fatalf("nil application slot rendered:\n%s", out)
		}
	})

	t.Run("application-sets", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
			"real-set": {Name: "real-set", Applications: []string{"junos-http"}},
			"nil-set":  nil,
		}
		var buf strings.Builder
		renderNoPanic(t, func() { (&Server{}).showApplications(cfg, &buf) })
		out := buf.String()
		if !strings.Contains(out, "real-set") {
			t.Fatalf("real application-set missing from output:\n%s", out)
		}
		if strings.Contains(out, "nil-set") {
			t.Fatalf("nil application-set slot rendered:\n%s", out)
		}
	})

	t.Run("feed-servers", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.DynamicAddress.FeedServers = map[string]*config.FeedServer{
			"real-feed": {Name: "real-feed", URL: "https://feeds.example/real.txt"},
			"nil-feed":  nil,
		}
		var buf strings.Builder
		renderNoPanic(t, func() { (&Server{}).showDynamicAddress(cfg, &buf) })
		out := buf.String()
		if !strings.Contains(out, "Feed server: real-feed") {
			t.Fatalf("real feed server missing from output:\n%s", out)
		}
		if strings.Contains(out, "nil-feed") {
			t.Fatalf("nil feed-server slot rendered:\n%s", out)
		}
	})

	t.Run("address-bindings", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.DynamicAddress.FeedServers = map[string]*config.FeedServer{
			"threat": {Name: "threat", URL: "https://feeds.example/threat.txt"},
		}
		cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
			"real-bind": {Name: "real-bind", FeedNames: []string{"threat"}},
			"nil-bind":  nil,
		}
		s := &Server{feedsFn: func() map[string]feeds.FeedInfo {
			return map[string]feeds.FeedInfo{
				"threat": {Prefixes: 5, LastFetch: time.Now()},
			}
		}}
		var buf strings.Builder
		renderNoPanic(t, func() { s.showDynamicAddress(cfg, &buf) })
		out := buf.String()
		if !strings.Contains(out, "real-bind: feeds threat, fail-mode retain") {
			t.Fatalf("real binding missing from output:\n%s", out)
		}
		if strings.Contains(out, "nil-bind") {
			t.Fatalf("nil binding slot rendered:\n%s", out)
		}
	})

	t.Run("address-book-addresses", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = &config.AddressBook{
			Addresses: map[string]*config.Address{
				"real-addr": {Name: "real-addr", Value: "10.0.0.0/24"},
				"nil-addr":  nil,
			},
		}
		var buf strings.Builder
		renderNoPanic(t, func() { (&Server{}).showAddressBook(cfg, &buf) })
		out := buf.String()
		if !strings.Contains(out, "real-addr") {
			t.Fatalf("real address missing from output:\n%s", out)
		}
		if strings.Contains(out, "nil-addr") {
			t.Fatalf("nil address slot rendered:\n%s", out)
		}
	})

	t.Run("address-book-sets", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = &config.AddressBook{
			AddressSets: map[string]*config.AddressSet{
				"outer":   {Name: "outer", Addresses: []string{"a1"}},
				"nil-set": nil,
			},
		}
		var buf strings.Builder
		renderNoPanic(t, func() { (&Server{}).showAddressBook(cfg, &buf) })
		out := buf.String()
		if !strings.Contains(out, "outer") {
			t.Fatalf("real address-set missing from output:\n%s", out)
		}
		if strings.Contains(out, "nil-set") {
			t.Fatalf("nil address-set slot rendered:\n%s", out)
		}
	})

	t.Run("ike-gateways", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.IPsec.Gateways = map[string]*config.IPsecGateway{
			"real-gw": {Name: "real-gw", Address: "203.0.113.1"},
			"nil-gw":  nil,
		}
		var buf strings.Builder
		renderNoPanic(t, func() { (&Server{}).showIKE(cfg, &buf) })
		out := buf.String()
		if !strings.Contains(out, "IKE gateway: real-gw") {
			t.Fatalf("real IKE gateway missing from output:\n%s", out)
		}
		if strings.Contains(out, "nil-gw") {
			t.Fatalf("nil IKE gateway slot rendered:\n%s", out)
		}
	})

	t.Run("ike-policies", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.IPsec.Gateways = map[string]*config.IPsecGateway{
			"gw-nil-pol": {Name: "gw-nil-pol", IKEPolicy: "pol-nil"},
			"gw-real-pol": {Name: "gw-real-pol", IKEPolicy: "pol-real",
				Address: "203.0.113.1"},
		}
		cfg.Security.IPsec.IKEPolicies = map[string]*config.IKEPolicy{
			"pol-nil":  nil,
			"pol-real": {Name: "pol-real", Mode: "main", Proposals: []string{"p1"}},
		}
		var buf strings.Builder
		renderNoPanic(t, func() { (&Server{}).showIKE(cfg, &buf) })
		out := buf.String()
		if !strings.Contains(out, "IKE policy:         pol-real") {
			t.Fatalf("real IKE policy missing from output:\n%s", out)
		}
		if !strings.Contains(out, "Mode:     main") {
			t.Fatalf("real IKE policy mode missing from output:\n%s", out)
		}
	})

	t.Run("ike-proposals", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.IPsec.Gateways = map[string]*config.IPsecGateway{
			"real-gw": {Name: "real-gw", Address: "203.0.113.1"},
		}
		cfg.Security.IPsec.IKEProposals = map[string]*config.IKEProposal{
			"real-prop": {Name: "real-prop", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", DHGroup: 14},
			"nil-prop":  nil,
		}
		var buf strings.Builder
		renderNoPanic(t, func() { (&Server{}).showIKE(cfg, &buf) })
		out := buf.String()
		if !strings.Contains(out, "real-prop: auth=pre-shared-keys") {
			t.Fatalf("real IKE proposal missing from output:\n%s", out)
		}
		if strings.Contains(out, "nil-prop") {
			t.Fatalf("nil IKE proposal slot rendered:\n%s", out)
		}
	})
}

// TestShowApplicationsRendersICMPTypeCode12903 pins the second half of
// #12903: an application constrained to one ICMP message type/code (#11340)
// must render the constraint. On master the row showed only
// `proto=icmp`, widening the rendered application to every type/code and
// hiding the narrowing the dataplane enforces.
func TestShowApplicationsRendersICMPTypeCode12903(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"my-ping":    {Name: "my-ping", Protocol: "icmp", ICMPType: icmpPtr(8), ICMPCode: icmpPtr(0)},
		"my-tcp-app": {Name: "my-tcp-app", Protocol: "tcp", DestinationPort: "443"},
	}
	var buf strings.Builder
	(&Server{}).showApplications(cfg, &buf)
	out := buf.String()

	if !strings.Contains(out, "icmp-type=8") || !strings.Contains(out, "icmp-code=0") {
		t.Fatalf("ICMP-constrained application lost its type/code constraint:\n%s", out)
	}
	// An application with no ICMP constraint must not gain one.
	for _, row := range strings.Split(out, "\n") {
		if strings.HasPrefix(row, "  my-tcp-app") && strings.Contains(row, "icmp-") {
			t.Fatalf("unconstrained application rendered an icmp token:\n%s", out)
		}
	}
}

// TestShowAddressBookRendersNestedAddressSets12903 pins the third half of
// #12903: an address-set that groups other sets must render those members
// (with the same `set:` prefix the local CLI uses) instead of presenting only
// its direct address members — an operator auditing a deny set would
// otherwise under-count what it matches.
func TestShowAddressBookRendersNestedAddressSets12903(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"a1": {Name: "a1", Value: "10.0.0.0/24"},
			"a2": {Name: "a2", Value: "192.0.2.0/24"},
		},
		AddressSets: map[string]*config.AddressSet{
			"inner": {Name: "inner", Addresses: []string{"a2"}},
			"outer": {Name: "outer", Addresses: []string{"a1"}, AddressSets: []string{"inner"}},
		},
	}
	var buf strings.Builder
	(&Server{}).showAddressBook(cfg, &buf)
	out := buf.String()

	if !strings.Contains(out, "members: a1, set:inner") {
		t.Fatalf("nested address-set member omitted from output:\n%s", out)
	}
	if !strings.Contains(out, "members: a2") {
		t.Fatalf("direct address member omitted from output:\n%s", out)
	}
}

// TestShowDynamicAddressRendersBindingsEnforced12903 pins the #12903
// `Dynamic Address Bindings` section of the gRPC text render: per-binding
// fail-mode and the shared feeds.BindingEnforcement verdict (the exact
// sentence the local CLI prints), so the remote and local `show security
// dynamic-address` surfaces cannot drift. On master the section was absent
// entirely — a remote operator could not see what the dataplane enforces for
// a feed-backed address name.
func TestShowDynamicAddressRendersBindingsEnforced12903(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DynamicAddress.FeedServers = map[string]*config.FeedServer{
		"threat": {Name: "threat", URL: "https://feeds.example/threat.txt"},
	}
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"badhosts":  {Name: "badhosts", FeedNames: []string{"threat"}},
		"mixedbind": {Name: "mixedbind", FeedNames: []string{"threat", "unknown-feed"}, FailMode: "drop"},
	}
	s := &Server{feedsFn: func() map[string]feeds.FeedInfo {
		return map[string]feeds.FeedInfo{
			"threat": {Prefixes: 5, LastFetch: time.Now()},
		}
	}}
	var buf strings.Builder
	s.showDynamicAddress(cfg, &buf)
	out := buf.String()

	if !strings.Contains(out, "Dynamic Address Bindings:") {
		t.Fatalf("bindings section missing from output:\n%s", out)
	}
	if !strings.Contains(out, "  badhosts: feeds threat, fail-mode retain") {
		t.Fatalf("retain binding row missing from output:\n%s", out)
	}
	if !strings.Contains(out, "    Enforced: current prefixes") {
		t.Fatalf("ready binding enforcement verdict missing from output:\n%s", out)
	}
	if !strings.Contains(out, "  mixedbind: feeds threat, unknown-feed, fail-mode drop") {
		t.Fatalf("drop binding row missing from output:\n%s", out)
	}
	// An unready constituent fails closed: the binding is unresolved, not
	// silently "current".
	if !strings.Contains(out, "Enforced: unresolved: a feed has no snapshot yet, so policies referencing this name are rejected and the previous-good policy set stays enforced") {
		t.Fatalf("unresolved binding enforcement verdict missing from output:\n%s", out)
	}
}

// TestShowTextDynamicAddressBindingsTopic12903 drives the same section
// through the ShowText RPC dispatch (topic `dynamic-address`) with a really
// committed config, proving the topic wiring — not just the extracted
// method — renders the binding verdicts.
func TestShowTextDynamicAddressBindingsTopic12903(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{
		"set security dynamic-address feed-server threat url https://feeds.example/threat.txt",
		"set security dynamic-address address-name badhosts profile feed-name threat",
	}
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	s := &Server{
		store: store,
		feedsFn: func() map[string]feeds.FeedInfo {
			return map[string]feeds.FeedInfo{
				"threat": {Prefixes: 3, LastFetch: time.Now()},
			}
		},
	}
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "dynamic-address"})
	if err != nil {
		t.Fatalf("ShowText(dynamic-address): %v", err)
	}
	out := resp.GetOutput()
	for _, want := range []string{
		"Feed server: threat",
		"Dynamic Address Bindings:",
		"  badhosts: feeds threat, fail-mode retain",
		"    Enforced: current prefixes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ShowText(dynamic-address) output missing %q:\n%s", want, out)
		}
	}
}
