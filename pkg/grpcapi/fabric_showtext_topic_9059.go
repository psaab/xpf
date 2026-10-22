package grpcapi

import (
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/optopic"
)

// #9059: ShowText is on the fabric allowlist as a METHOD, and it multiplexes
// ~127 topics behind that one method — so allowlisting it admits all of them.
//
// THE FILE ALREADY MAKES THIS ARGUMENT, four lines above, about a sibling:
//
//	SystemAction is deliberately absent: it multiplexes fabric-safe cross-node
//	cluster-failover with destructive node actions (zeroize/reboot/halt/
//	power-off) under ONE gRPC method, so a method-name allowlist that included
//	it would still expose zeroize. It is gated separately, by request-action,
//	in isFabricSafeSystemAction.
//
// Identical shape, identical remedy. ShowText sits in the same map with no
// equivalent per-topic gate, and fabricAllowlistUnaryInterceptor applied none.
//
// AND THE PRICING TABLE ALREADY EXISTS — on the other chain. authz_methods.go
// prices `test-policy:` / `test-routing:` / `test-zone:` at PermControl, calling
// them "policy reconnaissance … exactly the tier confusion this file exists to
// prevent", and TestEveryShowTextTopicHasAPermission_5278 keeps it exhaustive.
// It runs on the LOOPBACK principal chain only; the fabric listener shares no
// interceptor with it, which is itself pinned by
// TestFabricListenerDoesNotInstallThePrincipalGate_5278.
//
// WHY AN EXPLICIT TOPIC ALLOWLIST RATHER THAN REUSING THAT TABLE. The table
// prices a topic for a PRINCIPAL — it answers "may this login class read this".
// The fabric listener has no principal; its question is different and narrower:
// "does this node ever ASK a peer for this". Reusing a permission tier here
// would admit every topic priced at or below whatever tier the fabric was
// deemed to hold, which is the method-granularity mistake again, one level down.
//
// The allowlist's own comment says each entry is "a method the local node
// actually proxies". That is true at method granularity and false at topic
// granularity, and this restores it: both peer-proxy call sites send exactly
// one topic — server_show_forwarding.go and pkg/cli/cli_show_chassis.go both
// send "chassis-forwarding".
//
// What this actually withholds is RUNTIME state, and the honest framing matters
// for anyone weighing the change: the peer already receives the entire active
// config TEXT through config sync, so configuration is not the marginal
// disclosure. `route-all`, `security-log`, `commit-history`, the `nat-*-detail`
// topics and the `test-policy:` policy simulator are.
//
// #16136: the fabric admission bit now lives WITH the topic in the optopic
// registry (Entry.FabricAllowed), so a topic is priced, commanded, and
// fabric-classified in one edit. fabricAllowedShowTextTopics is the derived
// view the allowlist tests and gate read; it is built from the registry,
// never hand-edited.
var fabricAllowedShowTextTopics = func() map[string]bool {
	out := make(map[string]bool)
	for _, e := range optopic.ShowTextEntries() {
		if e.FabricAllowed {
			out[e.Key] = true
		}
	}
	return out
}()

// isFabricSafeShowText reports whether a ShowText request asks for a topic the
// local node actually proxies to a peer.
//
// A non-ShowText request returns false and is refused: this is only consulted
// once the method is known to be ShowText, and a request that fails to type-assert
// there is malformed rather than permitted. Fail closed, like its sibling.
func isFabricSafeShowText(req interface{}) bool {
	st, ok := req.(*pb.ShowTextRequest)
	if !ok {
		return false
	}
	return fabricAllowedShowTextTopics[st.GetTopic()]
}
