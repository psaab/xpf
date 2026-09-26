// #6532 invariant: NO fabric-allowlisted RPC may render a configured operator
// secret verbatim.
//
// The cluster-fabric gRPC listener is the only network-exposed gRPC surface
// (#4122). Its allowlist admits a small set of read/monitor RPCs, which means
// every one of them is reachable from the peer chassis over the fabric IP —
// not merely from loopback. ShowText{Topic:"snmp"} was rendering the SNMPv1/v2c
// community (the v1/v2c authenticator) in cleartext there long after the REST
// (#5315) and CLI (#4111) siblings were hardened, precisely because nothing
// asserted the property across the surface as a whole.
//
// This file asserts it as a property, not per-RPC:
//
//   - TestNoFabricAllowlistedRPCRendersAConfiguredSecret stages one config
//     carrying every secret leaf in the redaction SSOT (pkg/config
//     secretIndices / ast_redact.go), drives every allowlisted RPC, and scans
//     the rendered responses for the cleartext sentinels. The method set is
//     ENUMERATED from the live allowlist maps and the interceptor source — not
//     hardcoded — so a newly-allowlisted RPC fails the completeness gate until
//     it is explicitly audited.
//
//   - TestShowTextTopicAuditCoverageIsComplete extracts the ShowText topic set
//     from the dispatcher source so a newly-added topic must be added to the
//     audit sweep, rather than silently escaping it.
//
//   - TestGRPCAPINeverUnwrapsSecretCleartext pins the structural reason the
//     sweep finds only one class of leak: every operator secret except the SNMP
//     community is a config.Secret, whose String() masks it under %s/%v/%q/%x
//     (#2053). It reports two things a renderer can do to get past that — name
//     the Reveal accessor, or hand a Secret field to a one-argument call — and
//     covers the render paths the sweep cannot drive in-process (a nil
//     dataplane / IPsec manager / FRR short-circuits some renderers before they
//     format anything). It is SYNTACTIC and therefore has a hard limit, stated
//     on the test itself; it does not claim completeness.
//
//   - TestSecretUnwrapScannerDetectsBothForms and TestSecretFieldHarvestShapes
//     prove that guard can FAIL, for the scan and the field harvest
//     respectively. A structural check reporting "no violations" is worthless
//     until someone has shown it fires. That is not hypothetical here: this
//     scan shipped twice with shapes it claimed to cover producing no finding —
//     once with the Reveal branch behind an argument-count gate a zero-argument
//     method call never satisfies, and once blind to every parenthesized
//     callee. Both times the suite was green.
package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// fabricSecretConfig stages one instance of every secret leaf the redaction
// SSOT recognises (pkg/config/ast_redact.go secretIndices), each with a
// distinctive cleartext sentinel. It mirrors pkg/config's redactionSecretSet.
//
// The VRRP `authentication-key` leaf from that set is deliberately absent: the
// commit gate REJECTS it outright (#4288 — RFC 5798 VRRPv3 removed
// authentication), so it cannot exist in an active config and staging it makes
// Commit() fail rather than exercising a render.
var fabricSecretConfig = []string{
	"set security ike policy pol1 pre-shared-key ascii-text FAB6532-IKE-PSK",
	"set security ipsec vpn site-a pre-shared-key FAB6532-IPSEC-VPN-PSK",
	"set security ipsec vpn site-a bind-interface st0",
	"set protocols ospf area 0.0.0.0 interface ge-0-0-1 authentication md5 1 key FAB6532-OSPF-MD5KEY",
	"set protocols ospf area 0.0.0.0 interface ge-0-0-9 authentication simple-password FAB6532-OSPF-SIMPLE",
	// #9105: each key needs an explicit `authentication-type`. An absent type
	// is now refused at commit because it is indistinguishable at the render
	// site from a chosen PLAINTEXT one, and this fixture's whole subject is
	// that these secrets must not be rendered — so `md5` is the spelling that
	// matches its intent.
	"set protocols rip authentication-key FAB6532-RIP-AUTHKEY",
	"set protocols rip authentication-type md5",
	"set protocols isis authentication-key FAB6532-ISIS-AREA-AUTHKEY",
	"set protocols isis authentication-type md5",
	"set protocols isis interface ge-0-0-2 authentication-key FAB6532-ISIS-IFACE-AUTHKEY",
	"set protocols isis interface ge-0-0-2 authentication-type md5",
	"set protocols bgp group external authentication-key FAB6532-BGP-AUTHPW",
	"set system services web-management api-auth user admin password FAB6532-API-USER-PW",
	"set system services web-management api-auth api-key FAB6532-API-KEY-TOKEN",
	"set snmp v3 usm local-engine user admin authentication-sha256 authentication-password FAB6532-SNMPV3-AUTHPW",
	"set snmp v3 usm local-engine user admin privacy-des privacy-password FAB6532-SNMPV3-PRIVPW",
	"set snmp community FAB6532-SNMP-COMMUNITY authorization read-only",
	"set system services dhcp-local-server dynamic-dns tsig-secret FAB6532-TSIG-SECRET",
	"set system services dynamic-dns provider cf backend cloudflare",
	"set system services dynamic-dns provider cf api-token FAB6532-DDNS-APITOKEN",
	"set system services dynamic-dns provider r53 backend route53",
	"set system services dynamic-dns provider r53 aws-secret-key FAB6532-DDNS-AWSSECRET",
	"set system services dynamic-dns provider dy backend dyndns2",
	"set system services dynamic-dns provider dy password FAB6532-DDNS-HTTP-PW",
	"set interfaces wg0 tunnel wireguard private-key FAB6532-WG-PRIVKEY",
	"set interfaces wg0 tunnel wireguard peer p1 preshared-key FAB6532-WG-PSK",
	`set system root-authentication encrypted-password "$6$FABr6532$rootHASH6532rootHASH000000000000000000000000000000000000000000000000000000000000000000"`,
	`set system login user op authentication encrypted-password "$6$FABl6532$loginHASH6532loginHASH0000000000000000000000000000000000000000000000000000000000000000"`,
}

// fabricSecretSentinels is the cleartext token of each staged secret. Any of
// these appearing in a fabric-reachable render is a credential disclosure.
var fabricSecretSentinels = []string{
	"FAB6532-IKE-PSK", "FAB6532-IPSEC-VPN-PSK", "FAB6532-OSPF-MD5KEY",
	"FAB6532-OSPF-SIMPLE", "FAB6532-RIP-AUTHKEY", "FAB6532-ISIS-AREA-AUTHKEY",
	"FAB6532-ISIS-IFACE-AUTHKEY", "FAB6532-BGP-AUTHPW", "FAB6532-API-USER-PW",
	"FAB6532-API-KEY-TOKEN", "FAB6532-SNMPV3-AUTHPW", "FAB6532-SNMPV3-PRIVPW",
	"FAB6532-SNMP-COMMUNITY", "FAB6532-TSIG-SECRET", "FAB6532-DDNS-APITOKEN",
	"FAB6532-DDNS-AWSSECRET", "FAB6532-DDNS-HTTP-PW", "FAB6532-WG-PRIVKEY",
	"FAB6532-WG-PSK", "rootHASH6532rootHASH", "loginHASH6532loginHASH",
}

// showTextAuditTopics is the ShowText topic sweep. Every topic the dispatcher
// accepts must appear here — TestShowTextTopicAuditCoverageIsComplete derives
// the accepted set from the dispatcher source and fails on any omission.
// Parameterized (prefix:) topics carry a representative argument.
var showTextAuditTopics = []string{
	"address-book", "alarms", "alg", "application-identification-status",
	"applications", "backup-router", "bfd-peers", "bootstrap-import",
	"buffers", "buffers-detail",
	"chassis", "chassis-cluster", "chassis-cluster-control-plane-statistics",
	"chassis-cluster-data-plane-fairness", "chassis-cluster-data-plane-flows",
	"chassis-cluster-data-plane-interfaces", "chassis-cluster-data-plane-statistics",
	"chassis-cluster-fabric-statistics", "chassis-cluster-information",
	"chassis-cluster-interfaces", "chassis-cluster-ip-monitoring-status",
	"chassis-cluster-statistics", "chassis-cluster-status", "chassis-device-map",
	"chassis-device-map-candidates", "chassis-environment", "chassis-forwarding",
	"chassis-hardware", "commit-history", "core-dumps", "dhcp-relay",
	"dhcp-server", "dhcp-server-detail", "dhcp-server-dynamic-dns",
	"dhcp-server-dynamic-dns-detail", "dynamic-address", "event-options",
	"firewall", "flow-monitoring", "flow-monitoring-statistics",
	"flow-statistics", "flow-timeouts", "flow-traceoptions", "forwarding-options",
	"forwarding-options-port-mirroring", "ike", "interfaces-detail",
	"interfaces-extensive", "interfaces-statistics", "internet-options",
	"ipsec-statistics", "ipv6-router-advertisement", "kernel-upgrade",
	"lldp", "lldp-neighbors",
	"log", "login", "nat64", "nat-dest-rule-detail", "nat-nptv6",
	"nat-source-rule-detail", "nat-static", "ntp", "persistent-nat",
	"persistent-nat-detail", "policies-check", "policies-detail", "policies-hit-count",
	"policy-options", "root-authentication", "route-all", "route-detail",
	"route-instance", "route-map", "route-summary", "route-terse",
	"routing-instances", "routing-instances-detail", "routing-options", "rpm",
	"schedulers", "screen", "security-alarms", "security-alarms-detail",
	"security-log", "services-dynamic-dns", "services-dynamic-dns-detail",
	"services-ip-monitoring-status", "sessions-top:bytes", "sessions-top:packets",
	"snmp", "snmp-v3", "storage", "system-services", "system-syslog", "task",
	"tunnels", "version", "vlans", "wireguard", "wireguard-detail",
	"wireguard-public-key", "zones-detail",

	// Topics matched by equality outside the main switch.
	"class-of-service", "cos-classifier", "cos-forwarding-class",
	"cos-rewrite-rule", "cos-scheduler-map", "firewall-effective", "interfaces-queue",
	"monitor-security-flow", "screen-statistics-all",

	// Parameterized topics, with a representative argument each.
	"class-of-service:ge-0-0-1", "cos-classifier:c1",
	"cos-rewrite-rule:name=rw-dscp", "cos-scheduler-map:m1",
	"firewall-effective:inet", "firewall-effective-filter:f1",
	"firewall-filter:f1", "interfaces-queue:ge-0-0-1", "log:messages",
	"route-prefix:10.0.0.0/24", "route-protocol:bgp", "route-table:inet.0",
	"screen-ids-option:z", "screen-ids-option-detail:z", "screen-statistics:z",
	"test-policy:from=a,to=b", "test-routing:dest=10.0.0.0/24",
	"test-zone:interface=ge-0-0-1",
}

// fabricRPCProbe is how one fabric-reachable RPC gets audited. Exactly one of
// the two fields is set.
type fabricRPCProbe struct {
	// render drives the RPC and returns every string it emits (response bodies
	// AND error strings — an error message can leak a config value too).
	render func(t *testing.T, s *Server) []string

	// structuralOnly documents why an RPC cannot be driven in-process and what
	// covers it instead. Set only when render is nil.
	structuralOnly string
}

// fabricRPCProbes registers one probe per fabric-reachable RPC. The
// completeness gate in TestNoFabricAllowlistedRPCRendersAConfiguredSecret
// requires an entry for every method the fabric interceptors admit, so
// allowlisting a new RPC fails this file until someone audits it.
func fabricRPCProbes() map[string]fabricRPCProbe {
	return map[string]fabricRPCProbe{
		pb.BpfrxService_ShowText_FullMethodName: {
			render: func(t *testing.T, s *Server) []string {
				out := make([]string, 0, len(showTextAuditTopics))
				for _, topic := range showTextAuditTopics {
					resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
					if err != nil {
						out = append(out, fmt.Sprintf("topic=%s err=%v", topic, err))
						continue
					}
					out = append(out, fmt.Sprintf("topic=%s\n%s", topic, resp.Output))
				}
				return out
			},
		},
		pb.BpfrxService_GetStatus_FullMethodName: {
			render: func(t *testing.T, s *Server) []string {
				resp, err := s.GetStatus(context.Background(), &pb.GetStatusRequest{})
				return []string{fmt.Sprintf("%v|%v", resp, err)}
			},
		},
		pb.BpfrxService_GetSessions_FullMethodName: {
			render: func(t *testing.T, s *Server) []string {
				resp, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{})
				return []string{fmt.Sprintf("%v|%v", resp, err)}
			},
		},
		pb.BpfrxService_GetSessionSummary_FullMethodName: {
			render: func(t *testing.T, s *Server) []string {
				resp, err := s.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{})
				return []string{fmt.Sprintf("%v|%v", resp, err)}
			},
		},
		pb.BpfrxService_GetZonePairSummary_FullMethodName: {
			render: func(t *testing.T, s *Server) []string {
				resp, err := s.GetZonePairSummary(context.Background(), &pb.GetZonePairSummaryRequest{})
				return []string{fmt.Sprintf("%v|%v", resp, err)}
			},
		},
		pb.BpfrxService_ClearSessions_FullMethodName: {
			render: func(t *testing.T, s *Server) []string {
				resp, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{})
				return []string{fmt.Sprintf("%v|%v", resp, err)}
			},
		},
		pb.BpfrxService_SystemAction_FullMethodName: {
			// Not in fabricAllowedUnaryMethods — admitted by the separate
			// isFabricSafeSystemAction branch for the two cross-node
			// cluster-failover forms only. Audited because it IS fabric
			// reachable; the failover response carries RG ownership state, no
			// config render.
			render: func(t *testing.T, s *Server) []string {
				resp, err := s.SystemAction(context.Background(),
					&pb.SystemActionRequest{Action: "cluster-failover:1:node1"})
				return []string{fmt.Sprintf("%v|%v", resp, err)}
			},
		},
		pb.BpfrxService_MonitorInterface_FullMethodName: {
			// The one streaming RPC on the allowlist. It streams pre-formatted
			// TEXT frames of per-interface counter snapshots
			// (monitoriface.RenderTrafficSummary / RenderSingleInterface), and
			// it DOES read configuration: the interface set comes from the
			// active config (TrafficSummaryInterfaces, else
			// cfg.Interfaces.Interfaces) and the display names it prints come
			// from ResolveReth / LookupInterface. So it is audited like any
			// other renderer, not excused.
			//
			// Driving it is straightforward with a nil dataplane, exactly like
			// the unary probes above: the snapshot reads fail, the interface
			// NAMES still render, and monitorFrameSink aborts the stream after
			// the first frame so the 1s ticker loop returns at once.
			render: func(t *testing.T, s *Server) []string {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				sink := &monitorFrameSink{ctx: ctx}
				err := s.MonitorInterface(&pb.MonitorInterfaceRequest{}, sink)
				if err != nil && !errors.Is(err, errMonitorProbeDone) {
					t.Fatalf("MonitorInterface: %v", err)
				}
				if len(sink.frames) == 0 {
					t.Fatal("MonitorInterface rendered no frame — the probe is " +
						"vacuous; it must actually exercise the renderer")
				}
				return sink.frames
			},
		},
	}
}

// errMonitorProbeDone aborts MonitorInterface's stream after one frame.
var errMonitorProbeDone = errors.New("monitor probe: one frame captured")

// monitorFrameSink is a minimal grpc.ServerStreamingServer that records the
// frames MonitorInterface emits and then ends the stream. Only Context and
// Send are exercised; the embedded nil ServerStream satisfies the rest of the
// interface and would panic loudly if the handler ever reached for more.
type monitorFrameSink struct {
	grpc.ServerStream
	ctx    context.Context
	frames []string
}

func (m *monitorFrameSink) Context() context.Context { return m.ctx }

func (m *monitorFrameSink) Send(resp *pb.MonitorInterfaceResponse) error {
	m.frames = append(m.frames, resp.GetFrame())
	return errMonitorProbeDone
}

// newFabricSecretServer commits fabricSecretConfig and returns a Server over
// it. The dataplane / IPsec / FRR dependencies stay nil, matching the other
// pkg/grpcapi render tests: the config-render paths under audit read the typed
// active config, not those subsystems.
func newFabricSecretServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet(strings.Join(fabricSecretConfig, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	return &Server{store: store}
}

// fabricAdmittedMethods enumerates every method the fabric interceptors can
// admit: the two allowlist maps plus any method the interceptor source
// special-cases by name (today: SystemAction, via isFabricSafeSystemAction).
// Reading the interceptor source closes the hole a map-only enumeration would
// leave — a second special-cased admission would otherwise escape the audit.
//
// LIMIT, and why the canary below exists: the source scan is TEXTUAL and reads
// only the two interceptor function BODIES. It finds SystemAction because
// `pb.BpfrxService_SystemAction_FullMethodName` is written inline in
// fabricAllowlistUnaryInterceptor. Hoisting that constant into a helper — the
// way isFabricSafeSystemAction already holds the predicate — would silently
// drop the method from the audited set. Keep the method-name constants IN the
// interceptor bodies; if a refactor must move one, extend
// methodsNamedInInterceptors to follow it.
func fabricAdmittedMethods(t *testing.T) map[string]bool {
	t.Helper()
	admitted := map[string]bool{}
	for m := range fabricAllowedUnaryMethods {
		admitted[m] = true
	}
	for m := range fabricAllowedStreamMethods {
		admitted[m] = true
	}
	for _, m := range methodsNamedInInterceptors(t) {
		admitted[m] = true
	}

	// Canary for the limit above. SystemAction is known to be fabric-admitted
	// (isFabricSafeSystemAction), and it is reachable ONLY via the source scan
	// — it is in neither allowlist map. If the scan stops finding it, the scan
	// itself broke; failing here is what keeps that from being silent. This is
	// a floor on the enumeration, not a substitute for it: the audited set is
	// still derived, so a NEW special-cased method is still picked up.
	if !admitted[pb.BpfrxService_SystemAction_FullMethodName] {
		t.Fatalf("the interceptor source scan no longer finds SystemAction, which "+
			"IS fabric-admitted via isFabricSafeSystemAction (%s:%s). The "+
			"method-name constant was probably hoisted out of the interceptor "+
			"body — follow it in methodsNamedInInterceptors, or this audit "+
			"silently stops covering it.", interceptorSrc,
			"fabricAllowlistUnaryInterceptor")
	}
	return admitted
}

// interceptorSrc is the file holding the fabric allowlist interceptors.
const interceptorSrc = "server.go"

// methodsNamedInInterceptors returns the full method names referenced inside
// the two fabric allowlist interceptor bodies.
func methodsNamedInInterceptors(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile(interceptorSrc)
	if err != nil {
		t.Fatalf("read %s (the fabric interceptors moved? update interceptorSrc): %v",
			interceptorSrc, err)
	}
	var out []string
	for _, fn := range []string{
		"func (s *Server) fabricAllowlistUnaryInterceptor(",
		"func (s *Server) fabricAllowlistStreamInterceptor(",
	} {
		body := funcBody(t, string(src), fn)
		for _, m := range regexp.MustCompile(`pb\.BpfrxService_(\w+)_FullMethodName`).FindAllStringSubmatch(body, -1) {
			out = append(out, "/xpf.v1.BpfrxService/"+m[1])
		}
	}
	return out
}

// funcBody returns the source text of the function whose declaration starts
// with decl, up to the closing brace in column 0.
func funcBody(t *testing.T, src, decl string) string {
	t.Helper()
	i := strings.Index(src, decl)
	if i < 0 {
		t.Fatalf("%s: cannot find %q — the fabric interceptors were renamed or "+
			"moved; update this test so the audit keeps enumerating them",
			interceptorSrc, decl)
	}
	rest := src[i:]
	if end := strings.Index(rest, "\n}\n"); end >= 0 {
		return rest[:end]
	}
	return rest
}

// TestFabricSecretStagingIsReal guards the sweep against the worst failure
// mode of a "no secret appeared" assertion: passing because nothing was ever
// staged. A `set` line that the compiler silently drops (renamed leaf, changed
// grammar) would make every downstream scan vacuously green. Assert every
// sentinel is really in the committed active config, in cleartext, BEFORE
// trusting an absence downstream.
func TestFabricSecretStagingIsReal(t *testing.T) {
	s := newFabricSecretServer(t)
	active := s.store.ShowActive()
	for _, sentinel := range fabricSecretSentinels {
		if !strings.Contains(active, sentinel) {
			t.Errorf("secret sentinel %q is NOT in the committed active config — the "+
				"staging `set` line was dropped, so every scan for it downstream is "+
				"vacuous. Fix fabricSecretConfig.", sentinel)
		}
	}
	if n := len(fabricSecretSentinels); n < 20 {
		t.Errorf("only %d secret sentinels staged; the redaction SSOT "+
			"(pkg/config/ast_redact.go secretIndices) covers more — the sweep has "+
			"lost coverage", n)
	}
}

// TestNoFabricAllowlistedRPCRendersAConfiguredSecret is the #6532 invariant:
// drive every fabric-reachable RPC against a config carrying every secret leaf
// and assert no cleartext credential reaches the wire. It goes RED against
// pre-fix code (ShowText{snmp} emits the community).
//
// Its inputs are proven real by TestFabricSecretStagingIsReal above.
func TestNoFabricAllowlistedRPCRendersAConfiguredSecret(t *testing.T) {
	probes := fabricRPCProbes()

	// Completeness gate: a newly-allowlisted RPC must be audited, not silently
	// admitted. This is why the method set is enumerated, not hardcoded.
	for method := range fabricAdmittedMethods(t) {
		if _, ok := probes[method]; !ok {
			t.Fatalf("fabric-reachable RPC %s has no secret-render probe. It is "+
				"admitted on the network-exposed cluster-fabric listener, so it must "+
				"be audited for configured-secret renders (#6532): add an entry to "+
				"fabricRPCProbes.", method)
		}
	}

	s := newFabricSecretServer(t)
	for method, probe := range probes {
		if probe.render == nil {
			if probe.structuralOnly == "" {
				t.Errorf("probe %s has neither a render func nor a structuralOnly "+
					"rationale", method)
			}
			continue
		}
		t.Run(strings.TrimPrefix(method, "/xpf.v1.BpfrxService/"), func(t *testing.T) {
			for _, out := range probe.render(t, s) {
				for _, leak := range fabricSecretSentinels {
					if strings.Contains(out, leak) {
						t.Errorf("%s rendered the cleartext secret %q on the "+
							"network-exposed fabric surface (#6532):\n%s", method, leak, out)
					}
				}
			}
		})
	}
}

// TestShowTextTopicAuditCoverageIsComplete derives the topic set the ShowText
// dispatcher accepts from its source and asserts the audit sweep drives every
// one. Adding a topic that renders a secret without adding it here would
// otherwise slip past the sweep above.
func TestShowTextTopicAuditCoverageIsComplete(t *testing.T) {
	driven := map[string]bool{}
	for _, topic := range showTextAuditTopics {
		driven[topic] = true
		// A parameterized topic is driven as "prefix:arg"; record the bare
		// prefix form too so the source-derived "prefix:" matches it.
		if i := strings.Index(topic, ":"); i >= 0 {
			driven[topic[:i+1]] = true
		}
	}

	for _, topic := range dispatcherTopics(t) {
		if !driven[topic] {
			t.Errorf("ShowText topic %q is dispatched but not driven by the #6532 "+
				"fabric secret-render audit. ShowText is on the cluster-fabric "+
				"allowlist (#4122), so every topic it renders is reachable from the "+
				"peer chassis: add %q to showTextAuditTopics.", topic, topic)
		}
	}
}

// dispatcherTopics extracts every topic literal the ShowText dispatcher
// accepts: the `case` labels of its topic switch (server_show.go holds exactly
// one switch, `switch req.Topic`) plus the equality and prefix tests spread
// across the package's non-test sources.
func dispatcherTopics(t *testing.T) []string {
	t.Helper()

	src, err := os.ReadFile("server_show.go")
	if err != nil {
		t.Fatalf("read server_show.go (the ShowText dispatcher moved? update this "+
			"test so topic coverage keeps being enforced): %v", err)
	}
	if n := strings.Count(string(src), "\tswitch "); n != 1 {
		t.Fatalf("server_show.go has %d switch statements, expected exactly 1 "+
			"(`switch req.Topic`). The case-label extraction below is only "+
			"unambiguous while that holds — update this test.", n)
	}

	var topics []string
	caseRe := regexp.MustCompile(`(?m)^\tcase (.+):$`)
	strRe := regexp.MustCompile(`"([^"]+)"`)
	for _, m := range caseRe.FindAllStringSubmatch(string(src), -1) {
		for _, lit := range strRe.FindAllStringSubmatch(m[1], -1) {
			topics = append(topics, lit[1])
		}
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}
	topicRe := regexp.MustCompile(`req\.Topic == "([^"]+)"|HasPrefix\(req\.Topic, "([^"]+)"\)`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range topicRe.FindAllStringSubmatch(string(b), -1) {
			if m[1] != "" {
				topics = append(topics, m[1])
			}
			if m[2] != "" {
				topics = append(topics, m[2])
			}
		}
	}

	if len(topics) < 50 {
		t.Fatalf("extracted only %d ShowText topics from source — the dispatcher "+
			"shape changed and this audit is no longer enumerating it", len(topics))
	}
	return topics
}

// --- Structural guard: no cleartext unwrapping of a config.Secret ---
//
// TestGRPCAPINeverUnwrapsSecretCleartext pins the structural property the audit
// above rests on. Every operator secret in the config tree except the SNMP
// community is a config.Secret, whose String() renders "<redacted>" under
// %s/%v/%q/%x (#2053) — so a text renderer cannot leak one by accident.
//
// This guard detects TWO SHAPES. That is NOT the same as enumerating every way
// to defeat the redaction — Go's expression grammar is open and the RESIDUALS
// listed below are real. The two DETECTED shapes are:
//
//  1. Reveal(), the explicit cleartext accessor.
//  2. A CONVERSION. config.Secret is `type Secret string`
//     (pkg/config/secret.go), so `string(x.PSK)`, `[]byte(x.PSK)` or
//     `"p " + string(x.PSK)` yields the raw value without reaching String().
//
// Both matter most for the renderers the in-process sweep cannot drive:
// wireguard / ipsec-statistics / bfd-peers short-circuit on a nil dataplane,
// IPsec manager or FRR before formatting anything, so for those paths this
// guard is the only net. A leak there is invisible to the sweep.
//
// The scan is a pure function (scanSecretUnwraps) precisely so
// TestSecretUnwrapScannerDetectsBothForms can prove it FIRES, on synthetic
// source, for every shape it claims to catch. That meta-test is load-bearing:
// an all-clear from a scan nobody has proven can fail is indistinguishable
// from a broken scan, which is exactly how the Reveal() branch of an earlier
// revision of this file became unreachable dead code while still reporting
// PASS.
//
// RESIDUALS — shapes this guard does NOT flag, stated so the coverage claim
// above is not read as completeness:
//   - a COMPUTED argument. secretExprTail walks a DIRECT wrapper chain
//     (index / slice / deref / paren / selector) and returns "" for anything
//     else, so `Clear(x.PSK + "")`, `Clear([]config.Secret{x.PSK}[0])` and
//     `Clear(<-x.SecretChan)` pass the arity gate but do not resolve to a
//     harvested field name.
//   - `copy(dst, x.PSK)` and `append(dst, x.PSK...)` — two arguments, so the
//     arity gate does not reach them.
//   - reflection, and any unwrap through an interface value.
//
// SCOPE, and the HARD LIMIT.
//
// This guard is SYNTACTIC. It reads the AST; it does not resolve types. That
// is not a temporary state to be patched away — it is a ceiling, and four
// review rounds were spent discovering it one shape at a time. The honest
// statement of what it can and cannot do follows, and the ceiling is the
// important half.
//
// WHAT IT DETECTS
//
//  1. Any SELECTION named Reveal. Matching the selection rather than the call
//     covers `x.PSK.Reveal()`, `(x.PSK.Reveal)()`, a method value
//     `reveal := x.PSK.Reveal`, a method expression, an interface call and a
//     promoted embedded method, uniformly and without shape enumeration.
//
//  2. A ONE-ARGUMENT call whose argument names a Secret-bearing field. It does
//     NOT inspect the callee. Earlier revisions matched callee shapes —
//     `string`, `(string)`, `((string))`, `[]byte`, `[](byte)`, `([](byte))` —
//     and each fix was blind to one more, because the callee of a conversion
//     is a TYPE EXPRESSION whose grammar is open: `type Clear string;
//     Clear(x.PSK)` unwraps the secret and no builtin-name matching ever sees
//     it. Ignoring the callee closes that whole dimension at once.
//
// Two dimensions ARE closed exhaustively, by enumerating go/ast node kinds
// rather than source shapes: parenthesization (nothing about the callee is
// examined) and the argument's wrapper chain (secretExprTail enumerates every
// expression node that designates the same value — paren, star, index, index
// list, slice, type assertion, address-of).
//
// # THE HARD LIMIT — INDIRECTION THROUGH A VALUE
//
// The check fires on the SYNTAX at the point of use, so it sees a secret only
// where the field is named. It cannot follow a value:
//
//   - `s := gw.PSK; _ = string(s)` — a local, a parameter, or a helper return;
//   - a Secret-bearing field declared outside pkg/config, or behind a type
//     alias, so the harvest never learns its name;
//   - a handoff to a MULTI-argument call (`leak(ctx, x.PSK)`). One argument is
//     a deliberate line, not an oversight: the safe idiom
//     `fmt.Fprintf(buf, "%s", x.PSK)` is multi-argument and redacts correctly,
//     so flagging it would fire on every correct render and be tuned out. A
//     helper that unwraps internally is caught at ITS unwrap site if it lives
//     in this package, and is out of scope if it does not;
//   - `append(dst, secret...)`, `copy(dst, secret)`, ranging or reflection.
//
// Closing these needs real type resolution (go/types via
// golang.org/x/tools/go/packages, today only an INDIRECT dependency), or
// inverting the check to flag every conversion in the package against an
// explicit allowlist — 42 conversions in pkg/grpcapi as of this commit, so
// feasible but it puts test scaffolding into production source. The clean
// structural fix is upstream: making config.Secret a struct rather than a
// named string type would make `string(s)` fail to COMPILE and collapse this
// entire shape space to the single Reveal accessor. That is a pkg/config-wide
// change (Secret is currently comparable and used as a map key), so it belongs
// in its own issue, not here.
//
// FALSE POSITIVES — by design, and the right bias on a network-exposed
// surface, but disclosed rather than left to be discovered:
//
//   - EVERY selector named Reveal is flagged, whatever it selects — a method
//     on an unrelated type, a package member, even a struct field called
//     Reveal. No type resolution, so no way to tell them apart;
//   - the one-argument check matches a trailing IDENTIFIER, so an unrelated
//     local, parameter or field that merely shares a name with a Secret field
//     (`Password`, `PSK`) is flagged — it is not limited to real fields;
//   - any one-argument call is flagged, including provably harmless ones such
//     as `len(x.PSK)`, which cannot carry a secret in its int result.
//
// All are cheap to justify in review; a missed credential is not. There are
// zero such sites in pkg/grpcapi today.
func TestGRPCAPINeverUnwrapsSecretCleartext(t *testing.T) {
	secretFields := secretTypedFieldNames(t)

	// Floor against a silently-broken harvest (a parse change, a moved
	// package). Well below the true count because field NAMES dedupe — AuthKey
	// alone is declared four times — so the set is 13 today, not the ~25
	// declaration sites: APIKeys APIToken AWSSecretAccessKey AuthKey
	// AuthPassword ControlLinkAuthKey EncryptedPassword PSK Password
	// PresharedKeyHex PrivPassword TSIGSecret WgLocalPrivkeyHex.
	if len(secretFields) < 10 {
		t.Fatalf("harvested only %d config.Secret field names; the extraction "+
			"broke and the conversion half of this guard is near-vacuous: %v",
			len(secretFields), secretFields)
	}

	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		scanned++
		for _, find := range scanSecretUnwraps(fset, file, f, secretFields) {
			t.Errorf("%s: %s\n\tpkg/grpcapi serves the network-exposed "+
				"cluster-fabric listener (#4122), so a cleartext secret here can "+
				"reach the peer chassis (#6532). Format the config.Secret directly "+
				"— %%s/%%v/%%q/%%x all redact — or justify the unwrap here.",
				find.Where, find.Detail)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no package sources — the glob is wrong and this guard is vacuous")
	}
}

// TestSecretUnwrapScannerDetectsBothForms is the meta-test: it proves the scan
// above can actually FAIL. Without it, a green run means either "no violations"
// or "the scan is broken", and those are indistinguishable — an earlier
// revision gated the Reveal() branch behind `len(call.Args) != 1`, which is
// never true for a zero-argument method call, so that branch was unreachable
// while the test still passed. Every shape the doc block claims to catch gets
// a synthetic source here.
func TestSecretUnwrapScannerDetectsBothForms(t *testing.T) {
	secretFields := map[string]bool{"PSK": true, "APIKeys": true}

	cases := []struct {
		name string
		src  string
		want string // substring the finding must contain
	}{
		{
			name: "Reveal accessor",
			src:  "package p\nfunc f(x T) { _ = x.PSK.Reveal() }\n",
			want: "Reveal()",
		},
		{
			name: "string conversion",
			src:  "package p\nfunc f(x T) { _ = string(x.PSK) }\n",
			want: `field "PSK" to string(...)`,
		},
		{
			name: "byte slice conversion",
			src:  "package p\nfunc f(x T) { _ = []byte(x.PSK) }\n",
			want: `"PSK" to []byte(...)`,
		},
		{
			name: "rune slice conversion",
			src:  "package p\nfunc f(x T) { _ = []rune(x.PSK) }\n",
			want: `"PSK" to []rune(...)`,
		},
		{
			name: "uint8 slice conversion",
			src:  "package p\nfunc f(x T) { _ = []uint8(x.PSK) }\n",
			want: `"PSK" to []uint8(...)`,
		},
		{
			name: "conversion nested in a call argument",
			src:  "package p\nfunc f(x T) { g(\"%s\", string(x.PSK)) }\n",
			want: `"PSK"`,
		},
		{
			name: "conversion through a pointer deref",
			src:  "package p\nfunc f(x T) { _ = string(*x.PSK) }\n",
			want: `"PSK"`,
		},
		{
			name: "conversion of an indexed collection field (APIKeys []Secret)",
			src:  "package p\nfunc f(x T) { _ = string(x.APIKeys[i]) }\n",
			want: `"APIKeys"`,
		},

		// Parenthesized callees. All of these are legal Go that gofmt leaves
		// untouched, and every one of them put an *ast.ParenExpr where an
		// earlier revision looked for the callee directly — so all four
		// produced NO finding while the scanner claimed to cover them.
		{
			name: "parenthesized Reveal callee",
			src:  "package p\nfunc f(x T) { _ = (x.PSK.Reveal)() }\n",
			want: "Reveal()",
		},
		{
			name: "parenthesized string conversion",
			src:  "package p\nfunc f(x T) { _ = (string)(x.PSK) }\n",
			want: `"PSK" to (string)(...)`,
		},
		{
			name: "parenthesized byte slice conversion",
			src:  "package p\nfunc f(x T) { _ = ([]byte)(x.PSK) }\n",
			want: `"PSK" to ([]byte)(...)`,
		},
		{
			name: "doubly parenthesized conversion",
			src:  "package p\nfunc f(x T) { _ = ((string))(x.PSK) }\n",
			want: `"PSK" to ((string))(...)`,
		},
		{
			name: "parenthesized conversion argument",
			src:  "package p\nfunc f(x T) { _ = string((x.PSK)) }\n",
			want: `"PSK"`,
		},

		// A method VALUE binds the accessor without calling it at the binding
		// site. Detecting the selection covers this; a CallExpr-anchored check
		// cannot, because the call is `reveal()` with no selector at all.
		{
			name: "Reveal bound as a method value",
			src:  "package p\nfunc f(x T) { reveal := x.PSK.Reveal; _ = reveal() }\n",
			want: "Reveal()",
		},

		// Callee shapes. Since the check no longer inspects the callee, these
		// all take one code path — but they are enumerated anyway because they
		// are the contract, and four review rounds were lost to exactly these
		// shapes escaping one at a time.
		{
			name: "slice element type parenthesized",
			src:  "package p\nfunc f(x T) { _ = [](byte)(x.PSK) }\n",
			want: `"PSK"`,
		},
		{
			name: "slice type and element both parenthesized",
			src:  "package p\nfunc f(x T) { _ = ([](byte))(x.PSK) }\n",
			want: `"PSK"`,
		},
		{
			name: "parenthesized rune element",
			src:  "package p\nfunc f(x T) { _ = [](rune)(x.PSK) }\n",
			want: `"PSK"`,
		},
		{
			name: "parenthesized uint8 element",
			src:  "package p\nfunc f(x T) { _ = [](uint8)(x.PSK) }\n",
			want: `"PSK"`,
		},
		// The escape no callee-shape matching can ever close: a conversion to
		// a named string type declared anywhere. This is why the check stopped
		// inspecting the callee.
		{
			name: "conversion to a named string type (type Clear string)",
			src:  "package p\nfunc f(x T) { _ = Clear(x.PSK) }\n",
			want: `"PSK"`,
		},
		{
			name: "conversion to a package-qualified named type",
			src:  "package p\nfunc f(x T) { _ = other.Clear(x.PSK) }\n",
			want: `"PSK"`,
		},

		// Argument shapes — the dimension that IS still gated, on
		// secretExprTail's exhaustive wrapper enumeration.
		{
			name: "sliced field",
			src:  "package p\nfunc f(x T) { _ = string(x.PSK[:]) }\n",
			want: `"PSK"`,
		},
		{
			name: "sliced field with bounds",
			src:  "package p\nfunc f(x T) { _ = string(x.PSK[1:2]) }\n",
			want: `"PSK"`,
		},
		{
			name: "address-of field",
			src:  "package p\nfunc f(x T) { _ = string(*&x.PSK) }\n",
			want: `"PSK"`,
		},
		{
			name: "type-asserted field",
			src:  "package p\nfunc f(x T) { _ = string(x.PSK.(S)) }\n",
			want: `"PSK"`,
		},
		{
			name: "pointer deref of an indexed collection field",
			src:  "package p\nfunc f(x T) { _ = []byte(*x.APIKeys[i]) }\n",
			want: `"APIKeys"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "synthetic.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse synthetic source: %v", err)
			}
			finds := scanSecretUnwraps(fset, file, "synthetic.go", secretFields)
			if len(finds) == 0 {
				t.Fatalf("scanSecretUnwraps did NOT flag %s — the guard does not "+
					"cover a shape its documentation claims. Source:\n%s",
					tc.name, tc.src)
			}
			joined := finds[0].Detail
			if !strings.Contains(joined, tc.want) {
				t.Errorf("finding does not describe the violation: got %q, want it "+
					"to contain %q", joined, tc.want)
			}
		})
	}

	// Negative controls. Without these the scanner could pass every case above
	// by flagging unconditionally, and a guard that fires on correct code is
	// one reviewers learn to ignore.
	for _, tc := range []struct {
		name string
		src  string
	}{
		{
			// THE canonical safe render: multi-argument, and String() redacts.
			name: "formatted with %s is safe",
			src:  "package p\nfunc f(x T) { fmt.Fprintf(buf, \"psk %s\\n\", x.PSK) }\n",
		},
		{
			name: "unrelated single-argument conversion",
			src:  "package p\nfunc f(x T) { _ = string(x.Hostname) }\n",
		},
		{
			name: "presence check is not an unwrap",
			src:  "package p\nfunc f(x T) bool { return x.PSK != \"\" }\n",
		},
	} {
		t.Run("SAFE: "+tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "synthetic.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if finds := scanSecretUnwraps(fset, file, "synthetic.go", secretFields); len(finds) != 0 {
				t.Errorf("%s must NOT be flagged; got %d finding(s): %v",
					tc.name, len(finds), finds)
			}
		})
	}
}

// TestSecretFieldHarvestShapes proves the harvest half of the guard finds
// Secret-bearing fields through the declaration shapes it claims to cover. The
// live pkg/config tree exercises only a few of these today, so without
// synthetic sources the widened harvest would be asserted but untested — the
// same gap that let the scanner's parenthesized shapes ship unnoticed.
func TestSecretFieldHarvestShapes(t *testing.T) {
	cases := []struct {
		name string
		decl string
		want string
	}{
		{"plain field", "type A struct{ PSK Secret }", "PSK"},
		{"parenthesized type", "type A struct{ PSK (Secret) }", "PSK"},
		{"slice of Secret", "type A struct{ APIKeys []Secret }", "APIKeys"},
		{"array of Secret", "type A struct{ Keys [4]Secret }", "Keys"},
		{"pointer to Secret", "type A struct{ PSK *Secret }", "PSK"},
		{"map value Secret", "type A struct{ M map[string]Secret }", "M"},
		{"channel of Secret", "type A struct{ C chan Secret }", "C"},
		{"embedded Secret", "type A struct{ Secret }", "Secret"},
		{"nested anonymous struct", "type A struct{ Inner struct{ Token Secret } }", "Token"},
		{"slice of anonymous struct", "type A struct{ Rows []struct{ Token Secret } }", "Token"},
		{"pointer to anonymous struct", "type A struct{ P *struct{ Token Secret } }", "Token"},
		{"map value anonymous struct", "type A struct{ M map[string]struct{ Token Secret } }", "Token"},
		{"map KEY anonymous struct", "type A struct{ M map[struct{ Token Secret }]bool }", "Token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "s.go", "package config\n"+tc.decl+"\n", 0)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.decl, err)
			}
			got := map[string]bool{}
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.TYPE {
					continue
				}
				for _, spec := range gen.Specs {
					if ts, ok := spec.(*ast.TypeSpec); ok {
						collectSecretFieldNames(ts.Type, got)
					}
				}
			}
			if !got[tc.want] {
				t.Errorf("harvest missed %q in %s — a Secret declared this way "+
					"would not be matched by the conversion check, so unwrapping "+
					"it would go unreported. Got: %v", tc.want, tc.decl, got)
			}
		})
	}

	// Negative control: a plain string field must NOT be harvested, or the
	// conversion check degenerates into flagging every field name.
	t.Run("SAFE: plain string field is not harvested", func(t *testing.T) {
		fset := token.NewFileSet()
		file, _ := parser.ParseFile(fset, "s.go",
			"package config\ntype A struct{ Name string }\n", 0)
		got := map[string]bool{}
		for _, decl := range file.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok {
				for _, spec := range gen.Specs {
					if ts, ok := spec.(*ast.TypeSpec); ok {
						collectSecretFieldNames(ts.Type, got)
					}
				}
			}
		}
		if got["Name"] {
			t.Errorf("a plain string field must not be harvested; got %v", got)
		}
	})
}

// secretUnwrap is one violation found by scanSecretUnwraps.
type secretUnwrap struct {
	Where  string // "file.go:LINE"
	Detail string
}

// scanSecretUnwraps reports every cleartext unwrapping of a config.Secret in
// one file. The two detections are deliberately INDEPENDENT — neither shares a
// precondition with the other — because coupling them is what silently killed
// the Reveal branch once already: a zero-argument method call never has exactly
// one Arg, so an arg-count gate placed ahead of it disabled it.
//
// Both detections are also written against the SHAPE OF THE AST rather than
// the shape of the source a reviewer pictures. Go lets a callee be
// parenthesized — `(x.PSK.Reveal)()`, `(string)(x.PSK)`, `((string))(x.PSK)`
// are all legal and survive gofmt — which puts an *ast.ParenExpr where the
// naive check looks for the callee. That is why the Reveal detection matches
// the SELECTOR rather than the call (ast.Inspect reaches the selector however
// the call is written, and even when it is never called — a `reveal :=
// x.PSK.Reveal` method value binds the same cleartext accessor), and why the
// conversion detection unwraps parentheses before inspecting the callee.
func scanSecretUnwraps(fset *token.FileSet, file *ast.File, filename string, secretFields map[string]bool) []secretUnwrap {
	var out []secretUnwrap
	at := func(n ast.Node) string {
		return fmt.Sprintf("%s:%d", filename, fset.Position(n.Pos()).Line)
	}

	ast.Inspect(file, func(n ast.Node) bool {
		// (1) The Reveal cleartext accessor, matched on the SELECTION itself.
		// This covers `x.PSK.Reveal()`, the parenthesized `(x.PSK.Reveal)()`,
		// and a method VALUE (`reveal := x.PSK.Reveal`) uniformly — binding the
		// accessor is as much a cleartext path as calling it, and none of the
		// three depends on how the call is parenthesized.
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Reveal" {
			out = append(out, secretUnwrap{
				Where: at(sel),
				Detail: "references the config.Secret cleartext accessor Reveal(), " +
					"which returns the raw secret",
			})
			return true
		}

		// (2) A single-argument call applied to a Secret field.
		//
		// This deliberately does NOT inspect the callee. Four rounds of review
		// were spent patching callee SHAPES — `(string)(x)`, `((string))(x)`,
		// `[](byte)(x)`, `([](byte))(x)` — and each fix was blind to one more,
		// because the callee of a conversion is a TYPE EXPRESSION and the
		// grammar of type expressions is open: `type Clear string;
		// Clear(x.PSK)` unwraps the secret just as effectively and no amount of
		// builtin-name matching sees it.
		//
		// So the callee is not the discriminator. What matters is that a
		// Secret-typed field is handed to a one-argument call at all. Every
		// conversion — builtin, parenthesized, aliased, or a named string type
		// declared anywhere — is a one-argument call, so all of them land here
		// with no shape enumeration.
		//
		// One argument is the right line: the SAFE and idiomatic render,
		// `fmt.Fprintf(buf, "%s", x.PSK)`, is multi-argument and passes through
		// String()'s redaction. Flagging it too would make this guard fire on
		// every correct render and be tuned out.
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		name := secretExprTail(call.Args[0])
		if name == "" || !secretFields[name] {
			return true
		}
		out = append(out, secretUnwrap{
			Where: at(call),
			Detail: fmt.Sprintf("passes the config.Secret field %q to %s(...). "+
				"config.Secret is a named string type, so a conversion yields "+
				"the CLEARTEXT secret without ever reaching the String() "+
				"redaction", name, types.ExprString(call.Fun)),
		})
		return true
	})
	return out
}

// secretExprTail resolves an expression to the identifier it ultimately names —
// "PSK" for `cfg.Security.IKE.Policies[n].PSK`, `(x.PSK)`, `*x.PSK`,
// `x.PSK[:]` or `x.APIKeys[i]` — or "" if it names none.
//
// The wrapper cases below are an EXHAUSTIVE enumeration of the go/ast
// expression nodes that wrap another expression while still designating the
// same underlying value. That exhaustiveness is the point: this is one of the
// two dimensions of this guard that CAN be closed completely, and enumerating
// the node kinds closes it, whereas matching source shapes one at a time did
// not. The default case returns "" — an expression kind that is not a wrapper
// (a call, a composite literal, a binary expression) does not name a field.
func secretExprTail(e ast.Expr) string {
	for {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			return x.Sel.Name
		case *ast.Ident:
			return x.Name
		case *ast.ParenExpr: // (x.PSK)
			e = x.X
		case *ast.StarExpr: // *x.PSK
			e = x.X
		case *ast.IndexExpr: // x.APIKeys[i]
			e = x.X
		case *ast.IndexListExpr: // generic instantiation x.F[A, B]
			e = x.X
		case *ast.SliceExpr: // x.PSK[:]
			e = x.X
		case *ast.TypeAssertExpr: // x.PSK.(T)
			e = x.X
		case *ast.UnaryExpr: // &x.PSK
			if x.Op != token.AND {
				return ""
			}
			e = x.X
		default:
			return ""
		}
	}
}

// secretTypedFieldNames returns the names of every struct field whose type
// MENTIONS config.Secret, declared at FILE SCOPE in pkg/config — including
// collection and pointer shapes such as `APIKeys []Secret`
// (types_system.go), which a bare `field.Type == Ident("Secret")` match would
// miss even though `string(x.APIKeys[i])` is a direct field conversion.
//
// File scope matters: the SNMPCommunity MarshalJSON/MarshalYAML bodies declare
// LOCAL alias structs with a `Name Secret` field, and folding that generic
// name into the set would flag `string(x.Name)` all over the package. Walking
// only file-scope type declarations excludes them.
func secretTypedFieldNames(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	files, err := filepath.Glob(filepath.Join("..", "config", "*.go"))
	if err != nil {
		t.Fatalf("glob pkg/config: %v", err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				collectSecretFieldNames(ts.Type, out)
			}
		}
	}
	return out
}

// collectSecretFieldNames adds every field of typ whose type mentions Secret,
// recursing into nested anonymous structs. It looks THROUGH slice, array,
// pointer and map shapes on the way down, so a Secret carried inside
// `[]struct{ Token Secret }` or `map[string]*struct{ PSK Secret }` is
// harvested rather than skipped — a bare `typ.(*ast.StructType)` assertion
// stops at the first such wrapper.
//
// An EMBEDDED Secret (`struct { Secret }`) has no name in the AST but is
// selected as `x.Secret`, so it is harvested under that name.
func collectSecretFieldNames(typ ast.Expr, out map[string]bool) {
	// A map carries a struct on EITHER side, and `structTypeOf` can only
	// return one. Recurse into both halves explicitly so
	// `map[struct{ Key Secret }]struct{ Value Secret }` harvests BOTH — the
	// previous shape returned the key's struct and silently never visited the
	// value, while the doc claimed both sides were followed.
	for {
		p, ok := typ.(*ast.ParenExpr)
		if !ok {
			break
		}
		typ = p.X
	}
	if mt, ok := typ.(*ast.MapType); ok {
		collectSecretFieldNames(mt.Key, out)
		collectSecretFieldNames(mt.Value, out)
		return
	}
	st := structTypeOf(typ)
	if st == nil || st.Fields == nil {
		return
	}
	for _, field := range st.Fields.List {
		if typeMentionsSecret(field.Type) {
			if len(field.Names) == 0 {
				// Embedded field: selected by its type name.
				if n := secretExprTail(field.Type); n != "" {
					out[n] = true
				}
			}
			for _, n := range field.Names {
				out[n.Name] = true
			}
		}
		collectSecretFieldNames(field.Type, out)
	}
}

// structTypeOf looks through slice/array/pointer/map wrappers to the struct
// type underneath, or nil if there is none. A map is followed on BOTH sides:
// an anonymous struct is a legal comparable map KEY, so
// `map[struct{ PSK Secret }]bool` carries a Secret just as
// `map[string]struct{ PSK Secret }` does.
func structTypeOf(e ast.Expr) *ast.StructType {
	for {
		switch x := e.(type) {
		case *ast.StructType:
			return x
		case *ast.ArrayType:
			e = x.Elt
		case *ast.StarExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		case *ast.MapType:
			if st := structTypeOf(x.Key); st != nil {
				return st
			}
			e = x.Value
		default:
			return nil
		}
	}
}

// typeMentionsSecret reports whether a type expression names Secret anywhere —
// `Secret`, `(Secret)`, `[]Secret`, `[4]Secret`, `*Secret`,
// `map[string]Secret`, `chan Secret`. Parentheses are legal in a type
// expression (`PSK (Secret)` is a valid field declaration that gofmt
// preserves), so they are stripped here like everywhere else in this file.
func typeMentionsSecret(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "Secret"
	case *ast.ParenExpr:
		return typeMentionsSecret(x.X)
	case *ast.ArrayType:
		return typeMentionsSecret(x.Elt)
	case *ast.StarExpr:
		return typeMentionsSecret(x.X)
	case *ast.MapType:
		return typeMentionsSecret(x.Value) || typeMentionsSecret(x.Key)
	case *ast.ChanType:
		return typeMentionsSecret(x.Value)
	case *ast.SelectorExpr:
		return x.Sel.Name == "Secret"
	}
	return false
}
