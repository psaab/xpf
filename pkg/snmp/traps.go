package snmp

import (
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// SNMP trap categories (Junos `snmp trap-group <g> categories <cat>`). A
// notification is dispatched to a trap-group only if the group is scoped to the
// notification's category (or has no category scope = all). Link up/down traps
// are tagged snmpCategoryLink; future category-tagged traps reuse the same
// groupWantsCategory guard with their own category constant.
const snmpCategoryLink = "link"

// groupWantsCategory reports whether trap-group tg should receive a
// notification tagged with category cat. A group with NO categories configured
// receives EVERY category — the Junos default for a trap-group without a
// `categories` stanza. A group scoped to specific categories receives only
// those, so a group that omits (excludes) cat is skipped. Comparison is
// case-insensitive to match the schema's free-form category tokens (#5522).
func groupWantsCategory(tg *config.SNMPTrapGroup, cat string) bool {
	if tg == nil {
		return false
	}
	if len(tg.Categories) == 0 {
		return true // no scope = all categories (Junos default)
	}
	for _, c := range tg.Categories {
		if strings.EqualFold(strings.TrimSpace(c), cat) {
			return true
		}
	}
	return false
}

// SNMPv2-Trap PDU type (context-specific, constructed, tag 7).
const pduSNMPv2Trap = 0xa7

// SNMPv1 Trap-PDU type (context-specific, constructed, tag 4). RFC 1157.
const pduSNMPv1Trap = 0xa4

// snmpVersion1 is the message version field value for SNMPv1 (0). The v2c
// message version (1) is snmpVersion2c in agent.go.
const snmpVersion1 = 0

// tagIPAddress is the ASN.1 application tag (class application, primitive,
// number 0) for IpAddress / NetworkAddress — the agent-addr field of an
// SNMPv1 Trap-PDU.
const tagIPAddress = 0x40

// SNMPv1 generic-trap values (RFC 1157). specific-trap is 0 for these.
const (
	genericTrapLinkDown = 2
	genericTrapLinkUp   = 3
)

// Standard trap OIDs.
var (
	// snmpTrapOID.0: 1.3.6.1.6.3.1.1.4.1.0
	oidSnmpTrapOID = []int{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}

	// snmpTraps node: 1.3.6.1.6.3.1.1.5 — the enterprise field of an SNMPv1
	// Trap-PDU carrying a standard generic trap, per RFC 2576 §3.1
	// (SNMPv2->SNMPv1 notification mapping).
	oidSnmpTraps = []int{1, 3, 6, 1, 6, 3, 1, 1, 5}

	// linkDown: 1.3.6.1.6.3.1.1.5.3
	oidLinkDown = []int{1, 3, 6, 1, 6, 3, 1, 1, 5, 3}
	// linkUp: 1.3.6.1.6.3.1.1.5.4
	oidLinkUp = []int{1, 3, 6, 1, 6, 3, 1, 1, 5, 4}

	// ifIndex column: 1.3.6.1.2.1.2.2.1.1
	oidIfIndex = []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 1}
	// ifDescr column: 1.3.6.1.2.1.2.2.1.2
	oidIfDescr = []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 2}
	// ifOperStatus column: 1.3.6.1.2.1.2.2.1.8
	oidIfOperStatus = []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 8}
)

// buildLinkTrap builds an SNMPv2c trap PDU for a link up/down event.
func (a *Agent) buildLinkTrap(community string, linkUp bool, ifindex int, ifname string) []byte {
	// sysUpTime in hundredths of a second.
	uptime := int(time.Since(a.startTime).Milliseconds() / 10)

	// Choose the trap OID.
	trapOID := oidLinkDown
	operStatus := 2 // down
	if linkUp {
		trapOID = oidLinkUp
		operStatus = 1 // up
	}

	// Build varbinds:
	// 1. sysUpTime.0 — TimeTicks
	vb1OID := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oidSysUpTime))
	vb1Val := berEncodeTLV(tagTimeTicks, berEncodeTimeTicks(uptime))
	vb1 := berEncodeTLV(tagSequence, append(vb1OID, vb1Val...))

	// 2. snmpTrapOID.0 — OID of the trap type
	vb2OID := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oidSnmpTrapOID))
	vb2Val := berEncodeTLV(tagObjectIdentifier, berEncodeOID(trapOID))
	vb2 := berEncodeTLV(tagSequence, append(vb2OID, vb2Val...))

	// 3. ifIndex.<ifindex> — Integer
	ifIndexOID := append(append([]int{}, oidIfIndex...), ifindex)
	vb3OID := berEncodeTLV(tagObjectIdentifier, berEncodeOID(ifIndexOID))
	vb3Val := berEncodeIntegerTLV(ifindex)
	vb3 := berEncodeTLV(tagSequence, append(vb3OID, vb3Val...))

	// 4. ifDescr.<ifindex> — OctetString
	ifDescrOID := append(append([]int{}, oidIfDescr...), ifindex)
	vb4OID := berEncodeTLV(tagObjectIdentifier, berEncodeOID(ifDescrOID))
	vb4Val := berEncodeTLV(tagOctetString, []byte(ifname))
	vb4 := berEncodeTLV(tagSequence, append(vb4OID, vb4Val...))

	// 5. ifOperStatus.<ifindex> — Integer (1=up, 2=down)
	ifOperOID := append(append([]int{}, oidIfOperStatus...), ifindex)
	vb5OID := berEncodeTLV(tagObjectIdentifier, berEncodeOID(ifOperOID))
	vb5Val := berEncodeIntegerTLV(operStatus)
	vb5 := berEncodeTLV(tagSequence, append(vb5OID, vb5Val...))

	// Varbind list
	var vbList []byte
	vbList = append(vbList, vb1...)
	vbList = append(vbList, vb2...)
	vbList = append(vbList, vb3...)
	vbList = append(vbList, vb4...)
	vbList = append(vbList, vb5...)
	vbListEncoded := berEncodeTLV(tagSequence, vbList)

	// PDU body: request-id, error-status(0), error-index(0), varbinds
	requestID := rand.Int31()
	pduBody := berEncodeIntegerTLV(int(requestID))
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbListEncoded...)

	pduEncoded := berEncodeTLV(pduSNMPv2Trap, pduBody)

	// Message: version(v2c), community, PDU
	msgBody := berEncodeIntegerTLV(snmpVersion2c)
	msgBody = append(msgBody, berEncodeTLV(tagOctetString, []byte(community))...)
	msgBody = append(msgBody, pduEncoded...)

	return berEncodeTLV(tagSequence, msgBody)
}

// buildLinkTrapV1 builds an SNMPv1 Trap-PDU (RFC 1157) for a link up/down
// event, for a trap group configured `version v1` (#3948). A v1-only receiver
// drops the SNMPv2c trap buildLinkTrap emits, so a v1 group must send the
// distinct v1 PDU shape: the trap type is carried in the generic-trap /
// specific-trap / time-stamp fields (not as sysUpTime.0 + snmpTrapOID.0
// varbinds), and the message version field is 0. The enterprise is the
// snmpTraps node.
//
// #9123: agent-addr is derived from the source address this trap will actually
// leave from (agentAddrForTarget), NOT hardcoded to 0.0.0.0. The comment that
// used to justify the hardcode cited "RFC 2576 §3.1", which is the wrong
// direction of the mapping, and RFC 3584 §3.2's normative text requires the
// opposite: a notification originator sending over IP SHALL set agent-addr to
// its own IP address, and 0.0.0.0 is the fallback for a non-IP transport. See
// agent_addr_9123.go.
func (a *Agent) buildLinkTrapV1(community, target string, linkUp bool, ifindex int, ifname string) []byte {
	// sysUpTime in hundredths of a second.
	return a.buildLinkTrapV1WithUptime(community, target, linkUp, ifindex, ifname, int(time.Since(a.startTime).Milliseconds()/10))
}

// buildLinkTrapV1WithUptime is buildLinkTrapV1 with the time-stamp supplied by
// the caller. The trap worker uses it for deferred v1 jobs (#9917 F-134) with
// the uptime captured at event time, so a trap delivered after backlog carries
// the event's time-stamp rather than the delivery time's.
func (a *Agent) buildLinkTrapV1WithUptime(community, target string, linkUp bool, ifindex int, ifname string, uptime int) []byte {

	genericTrap := genericTrapLinkDown
	operStatus := 2 // down
	if linkUp {
		genericTrap = genericTrapLinkUp
		operStatus = 1 // up
	}

	// Varbinds: ifIndex, ifDescr, ifOperStatus. sysUpTime.0 and snmpTrapOID.0
	// are NOT repeated as varbinds in v1 — they map to the time-stamp field
	// and the generic-trap/enterprise fields respectively.
	ifIndexOID := append(append([]int{}, oidIfIndex...), ifindex)
	vb1OID := berEncodeTLV(tagObjectIdentifier, berEncodeOID(ifIndexOID))
	vb1Val := berEncodeIntegerTLV(ifindex)
	vb1 := berEncodeTLV(tagSequence, append(vb1OID, vb1Val...))

	ifDescrOID := append(append([]int{}, oidIfDescr...), ifindex)
	vb2OID := berEncodeTLV(tagObjectIdentifier, berEncodeOID(ifDescrOID))
	vb2Val := berEncodeTLV(tagOctetString, []byte(ifname))
	vb2 := berEncodeTLV(tagSequence, append(vb2OID, vb2Val...))

	ifOperOID := append(append([]int{}, oidIfOperStatus...), ifindex)
	vb3OID := berEncodeTLV(tagObjectIdentifier, berEncodeOID(ifOperOID))
	vb3Val := berEncodeIntegerTLV(operStatus)
	vb3 := berEncodeTLV(tagSequence, append(vb3OID, vb3Val...))

	var vbList []byte
	vbList = append(vbList, vb1...)
	vbList = append(vbList, vb2...)
	vbList = append(vbList, vb3...)
	vbListEncoded := berEncodeTLV(tagSequence, vbList)

	// Trap-PDU body: enterprise, agent-addr, generic-trap, specific-trap,
	// time-stamp, variable-bindings.
	var pduBody []byte
	pduBody = append(pduBody, berEncodeTLV(tagObjectIdentifier, berEncodeOID(oidSnmpTraps))...)
	agentAddr := agentAddrForTarget(target)
	pduBody = append(pduBody, berEncodeTLV(tagIPAddress, agentAddr[:])...)
	pduBody = append(pduBody, berEncodeIntegerTLV(genericTrap)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...) // specific-trap
	pduBody = append(pduBody, berEncodeTLV(tagTimeTicks, berEncodeTimeTicks(uptime))...)
	pduBody = append(pduBody, vbListEncoded...)

	pduEncoded := berEncodeTLV(pduSNMPv1Trap, pduBody)

	// Message: version(v1=0), community, PDU.
	msgBody := berEncodeIntegerTLV(snmpVersion1)
	msgBody = append(msgBody, berEncodeTLV(tagOctetString, []byte(community))...)
	msgBody = append(msgBody, pduEncoded...)

	return berEncodeTLV(tagSequence, msgBody)
}

// buildLinkTrapsForVersion returns the pre-built trap packet(s) a trap group
// with the given configured version emits for a link event (#3948). Junos
// trap-group version semantics: "v1" emits an SNMPv1 Trap-PDU, "v2" (or an
// empty/unspecified value — the default) emits an SNMPv2c trap, and "all"
// emits BOTH. Any unrecognized value defaults to v2c (the pre-#3948 behavior)
// rather than dropping the notification.
//
// #9123: it now takes the target, because the v1 PDU carries an agent-addr that
// must agree with the source address the trap will leave from. On a multi-homed
// box that differs per target, so the packet is built per target rather than
// once per group.
func (a *Agent) buildLinkTrapsForVersion(community, version, target string, linkUp bool, ifindex int, ifname string) [][]byte {
	switch version {
	case "v1":
		return [][]byte{a.buildLinkTrapV1(community, target, linkUp, ifindex, ifname)}
	case "all":
		return [][]byte{
			a.buildLinkTrapV1(community, target, linkUp, ifindex, ifname),
			a.buildLinkTrap(community, linkUp, ifindex, ifname),
		}
	default: // "v2", "" (unspecified), or anything else -> v2c
		return [][]byte{a.buildLinkTrap(community, linkUp, ifindex, ifname)}
	}
}

// sendTrap sends a pre-built trap packet to a single target on port 162. It is
// the default value of Agent.trapSender (#5023); tests inject a slow/blocking
// or mock sender per-Agent instead of mutating a shared package global that
// races the running trap worker's read.
func sendTrap(target string, pkt []byte) error {
	// Ensure the target has a port.
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "162"
	}
	addr := net.JoinHostPort(host, port)

	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	// #9025: bound the WRITE, not just the dial. A connected-UDP Write can block
	// indefinitely on a full socket send buffer (ENOBUFS / a congested or down
	// egress path parks the goroutine in the netpoller until the buffer drains)
	// — the same fact pkg/flowexport/transport.go records (#4423 H07) and the
	// same one pkg/logging/syslog.go used to deny.
	//
	// It matters more here than the dial timeout does, because the trap worker
	// is SINGLE AND SERIAL: one backpressured target head-of-line-blocks traps
	// to every HEALTHY target until the bounded queue fills, and Stop() waits on
	// trapWG, so an uninterruptible write also delays shutdown. The queue
	// (#2991) already stops a caller blocking; this stops one dead receiver
	// monopolising the worker.
	//
	// Sized to match the dial timeout above so a single target's worst case
	// stays symmetric and bounded at 2s per leg. Best-effort: a conn that does
	// not support deadlines still gets its Write, just unbounded.
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("write to %s: %w", addr, err)
	}
	return nil
}

// NotifyLinkDown sends an SNMPv2c linkDown trap to all configured trap targets.
func (a *Agent) NotifyLinkDown(ifindex int, ifname string) {
	a.sendLinkTraps(false, ifindex, ifname)
}

// NotifyLinkUp sends an SNMPv2c linkUp trap to all configured trap targets.
func (a *Agent) NotifyLinkUp(ifindex int, ifname string) {
	a.sendLinkTraps(true, ifindex, ifname)
}

// sendLinkTraps builds and sends link traps to all configured trap group targets.
func (a *Agent) sendLinkTraps(linkUp bool, ifindex int, ifname string) {
	// Read the live config under cfgMu — the same lock UpdateConfig swaps it
	// under — so a commit-time reconcile cannot race trap delivery.
	cfg := a.snapshotCfg()

	if cfg == nil || len(cfg.TrapGroups) == 0 {
		return
	}

	community := selectTrapCommunity(cfg)

	direction := "down"
	if linkUp {
		direction = "up"
	}

	// Enqueue one job per emitted packet. The trap PDU shape is a per-trap-group
	// setting (#3948): a `version v1` group gets an SNMPv1 Trap-PDU,
	// `v2`/unspecified a v2c trap, and `all` both. The v2c packet is built here
	// (pure BER, no I/O) while the v1 packet is built on the trap worker: its
	// agent-addr costs a DNS lookup plus an up-to-2s dial per target, which
	// must not serialize on the link monitor behind K transitions x T targets
	// (#9917 F-134). The blocking dial/write happens on the trap worker so a
	// dead or slow target never stalls the link monitor (#2991). Iterate trap
	// groups in deterministic (sorted) order so log output and dispatch
	// ordering are stable across runs.
	//
	// uptime is captured once per event for the deferred v1 jobs, so their
	// time-stamps agree with each other and with event time.
	uptime := int(time.Since(a.startTime).Milliseconds() / 10)
	for _, tg := range sortedTrapGroups(cfg) {
		// #5522: enforce the trap-group category filter. A link trap is in the
		// "link" category; a group scoped to exclude link (e.g. `categories
		// [configuration]`) must NOT receive it. A group with no `categories`
		// stanza receives all categories (Junos default), so groupWantsCategory
		// returns true for it. Without this gate the configured filter was
		// silently inert — the discarded-Categories filter bypass.
		if !groupWantsCategory(tg, snmpCategoryLink) {
			continue
		}
		for _, target := range tg.Targets {
			// #9123: the v1 agent-addr is derived from the source address
			// toward THIS target, so the v1 build stays per target -- it just
			// runs on the worker now instead of the caller. The v2c packet
			// carries no agent-addr and is built here, unaffected.
			switch tg.Version {
			case "v1":
				a.enqueueTrap(trapJob{
					target: target, group: tg.Name, event: "link" + direction,
					iface: ifname, ifindex: ifindex,
					deferredV1: true, community: community, linkUp: linkUp, uptime: uptime,
				})
			case "all":
				a.enqueueTrap(trapJob{
					target: target, group: tg.Name, event: "link" + direction,
					iface: ifname, ifindex: ifindex,
					deferredV1: true, community: community, linkUp: linkUp, uptime: uptime,
				})
				for _, pkt := range a.buildLinkTrapsForVersion(community, "v2", target, linkUp, ifindex, ifname) {
					a.enqueueTrap(trapJob{
						target: target, pkt: pkt, group: tg.Name,
						event: "link" + direction, iface: ifname, ifindex: ifindex,
					})
				}
			default: // "v2", "" (unspecified), or anything else -> v2c
				for _, pkt := range a.buildLinkTrapsForVersion(community, tg.Version, target, linkUp, ifindex, ifname) {
					a.enqueueTrap(trapJob{
						target: target, pkt: pkt, group: tg.Name,
						event: "link" + direction, iface: ifname, ifindex: ifindex,
					})
				}
			}
		}
	}
}

// selectTrapCommunity picks the v2c trap community deterministically (#2989).
// SNMPConfig.Communities is a Go map, whose iteration order is randomized, so
// ranging over it and breaking on the first entry produced a different
// community per process run when more than one community was configured —
// collectors that accept only one community saw flaky traps and a less
// privileged community could leak through the wrong credential boundary. We
// instead pick the lexicographically-first configured community, a stable and
// predictable selection. When no community is configured the v2c default
// "public" is used (the configured set authorizes the trap on the wire and an
// empty set has no on-wire credential to assert).
func selectTrapCommunity(cfg *config.SNMPConfig) string {
	if cfg == nil || len(cfg.Communities) == 0 {
		return "public"
	}
	names := make([]string, 0, len(cfg.Communities))
	for name := range cfg.Communities {
		names = append(names, name)
	}
	sort.Strings(names)
	return names[0]
}

// sortedTrapGroups returns the configured trap groups in deterministic
// (name-sorted) order. The TrapGroups map iteration order is randomized; a
// stable order keeps dispatch and log output reproducible.
func sortedTrapGroups(cfg *config.SNMPConfig) []*config.SNMPTrapGroup {
	if cfg == nil || len(cfg.TrapGroups) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.TrapGroups))
	for name := range cfg.TrapGroups {
		names = append(names, name)
	}
	sort.Strings(names)
	groups := make([]*config.SNMPTrapGroup, 0, len(names))
	for _, name := range names {
		groups = append(groups, cfg.TrapGroups[name])
	}
	return groups
}

// normalizeTrapTarget maps a trap job's target spelling to its per-target
// accounting key (#9917 F-140): host-only and host:port spellings of one
// receiver share one cap, since sendTrap dials both at :162, and numeric IPs
// canonicalize (2001:0db8::9 and 2001:db8::9 key together) so spelling games
// cannot multiply one receiver's share. Hostnames keep their given spelling:
// DNS aliases still count separately -- resolving them at enqueue would put a
// DNS lookup back on the link-monitor path -- and so do case variants.
func normalizeTrapTarget(target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = target, "162"
	}
	if port == "" {
		port = "162"
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	return net.JoinHostPort(host, port)
}

// decTrapPerTarget releases one queued slot for a normalized target key. The
// worker calls it exactly once per dequeue -- sent, abandoned, or drained --
// pairing every enqueue-time increment, and the key is deleted at zero so the
// map tracks live backlog only. Safe on a nil map (a read plus a delete, both
// no-ops), so bare-struct agents that never admitted need no init.
func (a *Agent) decTrapPerTarget(key string) {
	a.mu.Lock()
	if n := a.trapPerTarget[key]; n <= 1 {
		delete(a.trapPerTarget, key)
	} else {
		a.trapPerTarget[key] = n - 1
	}
	a.mu.Unlock()
}

// enqueueTrap hands a pre-built trap to the async worker (#2991). It starts the
// worker on first use (so both NewAgent and bare-struct test agents get it) and
// never blocks the caller: when the bounded queue is full the trap is dropped
// and trapsDropped is incremented. Dropping is the correct backpressure policy
// here — the queue only fills when targets are not draining, and blocking the
// link monitor on SNMP observability is exactly the failure #2991 fixes.
func (a *Agent) enqueueTrap(job trapJob) {
	a.mu.Lock()
	if a.stopped {
		// #4916: the agent has been stopped (day-2 disable / rotation). Never
		// start a worker or enqueue a post-Stop trap — dropping here is what
		// guarantees no trap reaches a removed/rotated receiver after Stop.
		a.mu.Unlock()
		dropped := a.trapsDropped.Add(1)
		slog.Warn("SNMP trap dropped: agent stopped",
			"target", job.target, "group", job.group,
			"event", job.event, "iface", job.iface, "dropped_total", dropped)
		return
	}
	a.trapWorkerOnce.Do(func() {
		if a.trapQueue == nil {
			a.trapQueue = make(chan trapJob, trapQueueDepth)
		}
		if a.trapStop == nil {
			a.trapStop = make(chan struct{})
		}
		a.trapWG.Add(1)
		go a.trapWorker(a.trapQueue, a.trapStop)
	})
	if a.trapPerTarget == nil {
		a.trapPerTarget = make(map[string]int)
	}
	// C180-026: publish under the SAME a.mu that Stop takes to set stopped /
	// close trapStop, so an enqueue and a Stop are strictly serialized. This
	// makes shutdown accounting EXACT (accepted == delivered + trapsDropped
	// with no residual):
	//
	//   - If this enqueue wins the lock, it sends into the buffered queue (or
	//     counts a queue-full drop) BEFORE Stop can close trapStop. The worker
	//     only drains on stop, so close(trapStop) happens-after this send, and
	//     the worker's shutdown drain (countAbandonedTraps) counts the buffered
	//     job — it cannot have exited before the job was queued.
	//   - If Stop wins the lock, it sets stopped and closes trapStop first; this
	//     enqueue then observes stopped above and drops+counts.
	//
	// Either way the job is delivered or counted exactly once. Before this the
	// send ran AFTER unlocking, so an enqueue that passed the stopped check
	// could buffer into an orphaned queue after the worker had already drained
	// and exited — a job neither sent nor counted. The send is NON-BLOCKING (a
	// buffered channel + default), and the worker never takes a.mu, so holding
	// the lock across the send cannot deadlock on a slow/absent reader: a full
	// queue drops immediately.
	// #9917 F-140: per-target admission cap, binding only under shared-queue
	// pressure. One receiver past maxPerTargetTrapQueue sheds its new traps
	// here -- but only once the queue holds trapCapPressureThreshold jobs, so
	// healthy fan-out while the worker is transiently stalled still absorbs
	// below half-full exactly as the un-capped queue would. This is one
	// decision with three mutually exclusive outcomes -- cap-drop,
	// queue-full-drop, admit -- so every enqueue counts exactly one outcome
	// and the C180-026 accepted == delivered + dropped exactness holds.
	// len(chan) under mu is approximate under a draining worker, which is fine
	// for a pressure heuristic: both sides of the threshold shed-or-admit
	// exactly once either way.
	targetKey := normalizeTrapTarget(job.target)
	if len(a.trapQueue) >= trapCapPressureThreshold && a.trapPerTarget[targetKey] >= maxPerTargetTrapQueue {
		a.mu.Unlock()
		dropped := a.trapsDropped.Add(1)
		slog.Warn("SNMP trap dropped: per-target queue cap reached",
			"target", job.target, "group", job.group,
			"event", job.event, "iface", job.iface, "dropped_total", dropped)
		return
	}
	sent := false
	select {
	case a.trapQueue <- job:
		sent = true
	default:
	}
	if sent {
		// Increment ONLY on a successful send: incrementing before the send
		// would leak a slot on every queue-full drop (no dequeue ever pairs
		// it) and drift the target toward a permanent cap-out.
		a.trapPerTarget[targetKey]++
	}
	a.mu.Unlock()
	if sent {
		return
	}
	dropped := a.trapsDropped.Add(1)
	slog.Warn("SNMP trap queue full, dropping trap",
		"target", job.target, "group", job.group,
		"event", job.event, "iface", job.iface, "dropped_total", dropped)
}

// trapWorker drains the trap queue, performing the blocking dial/write for each
// queued trap off the link-monitor goroutine (#2991). A single worker bounds
// goroutine growth and serializes the slow dials; the queue capacity bounds
// memory.
//
// #4916: the worker selects on stop as well as the queue and re-checks stop
// before every send, so a Stop() ABANDONS the queued backlog (no trap is
// delivered to a removed/rotated receiver after the authorizing config was
// revoked) and the goroutine always exits — no leak per disable/re-enable
// cycle. The queue and stop channel are passed in (rather than read from the
// struct) so the worker never races Stop's field access. Stop waits on trapWG.
//
// C180-026: the abandoned backlog is ACCOUNTED for — the worker counts
// every dequeued-but-undelivered job (whether Stop raced the re-check or the
// sender returned an error) plus every job left buffered in the queue into
// trapsDropped exactly once before exiting. Before this, Stop discarded the
// queued link-state traps (during SNMP disable / target rotation / shutdown)
// while trapsDropped omitted them, so the drop total under-reported — it
// reflected only queue-full and post-Stop-enqueue drops. The worker is the SOLE
// reader of the queue, so the drain removes each job once and no other
// goroutine can double-count it.
func (a *Agent) trapWorker(queue chan trapJob, stop chan struct{}) {
	defer a.trapWG.Done()
	// Snapshot the sender once at worker start. It is set at construction
	// (NewAgent) or by a test on its own Agent before the worker is lazily
	// started, so this read never races a concurrent write (#5023). A
	// bare-struct Agent that never set the field falls back to sendTrap.
	send := a.trapSender
	if send == nil {
		send = sendTrap
	}
	for {
		select {
		case <-stop:
			// Stop fired with no job in hand: account for whatever remains
			// buffered in the queue, then exit.
			a.countAbandonedTraps(queue)
			return
		case job, ok := <-queue:
			if !ok {
				return
			}
			// #9917 F-140: release this job's per-target slot. The receive above
			// ran with no lock held; only this map update takes a.mu, and it
			// performs no chan operation, so it cannot deadlock against
			// enqueueTrap's send-under-mu.
			a.decTrapPerTarget(normalizeTrapTarget(job.target))
			// Re-check stop before delivering: the outer select picks
			// randomly when both cases are ready, so a job dequeued
			// concurrently with Stop must not be sent after Stop.
			select {
			case <-stop:
				// This job was dequeued but must not be sent (Stop raced the
				// outer select). Count it, then account for the rest of the
				// buffered backlog, then exit.
				dropped := a.trapsDropped.Add(1)
				slog.Warn("SNMP trap abandoned on stop, dropping trap",
					"target", job.target, "group", job.group,
					"event", job.event, "iface", job.iface, "dropped_total", dropped)
				a.countAbandonedTraps(queue)
				return
			default:
			}
			pkt := job.pkt
			if job.deferredV1 {
				// #9917 F-134: build the v1 Trap-PDU here, on the worker. The
				// agent-addr dial runs off the link monitor; the deferred build
				// wins over any carried pkt by the trapJob contract.
				pkt = a.buildLinkTrapV1WithUptime(job.community, job.target, job.linkUp, job.ifindex, job.iface, job.uptime)
				// #4916: the build above can block up to agentAddrDialTimeout,
				// so re-check stop before delivering -- a Stop that landed
				// mid-build must still abandon this trap rather than deliver
				// it to a removed/rotated receiver. Worst-case Stop latency
				// grows by one agent-addr dial for a deferred job in flight.
				select {
				case <-stop:
					dropped := a.trapsDropped.Add(1)
					slog.Warn("SNMP trap abandoned on stop, dropping trap",
						"target", job.target, "group", job.group,
						"event", job.event, "iface", job.iface, "dropped_total", dropped)
					a.countAbandonedTraps(queue)
					return
				default:
				}
			}
			if err := send(job.target, pkt); err != nil {
				dropped := a.trapsDropped.Add(1)
				slog.Warn("SNMP trap send failed, counting as dropped",
					"target", job.target, "group", job.group,
					"event", job.event, "iface", job.iface,
					"err", err, "dropped_total", dropped)
			} else {
				slog.Info("SNMP trap sent",
					"target", job.target, "group", job.group,
					"event", job.event, "iface", job.iface, "ifindex", job.ifindex)
			}
		}
	}
}

// countAbandonedTraps drains the trap queue without blocking, counting every
// buffered-but-undelivered job into trapsDropped exactly once. It runs only
// from the trap worker at shutdown (after stop was observed); the worker is the
// sole reader of the queue, so no other goroutine removes jobs concurrently and
// no job is double-counted. The non-blocking default terminates the drain when
// the buffer is empty.
//
// C180-026: this drain now counts EVERY buffered job, not just the common
// backlog. enqueueTrap publishes to the queue under the same a.mu that Stop
// takes to close trapStop, so any job admitted to the queue is buffered strictly
// before close(trapStop) is observable — the worker cannot have drained and
// exited before the job was queued. Combined with the dequeued-but-unsent count
// in trapWorker, shutdown accounting is exact: accepted == delivered +
// trapsDropped, with no post-drain residual.
func (a *Agent) countAbandonedTraps(queue chan trapJob) {
	for {
		select {
		case job, ok := <-queue:
			if !ok {
				return
			}
			a.decTrapPerTarget(normalizeTrapTarget(job.target))
			dropped := a.trapsDropped.Add(1)
			slog.Warn("SNMP trap abandoned on stop, dropping trap",
				"target", job.target, "group", job.group,
				"event", job.event, "iface", job.iface, "dropped_total", dropped)
		default:
			return
		}
	}
}
