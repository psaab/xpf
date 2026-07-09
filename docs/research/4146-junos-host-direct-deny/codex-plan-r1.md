The live r2 at `69056f7bf`—including the uncommitted scheduler exclusion—is not implementation-ready. Direction (b) is valid, but the proposed deny-term projection is not semantics-preserving; I made no repository changes.

1. LOCUS — CONFIRMED-SOUND, with narrower wording

A normal direct packet bypasses userspace-dp:

- A `PASS_TO_KERNEL` session hit returns `cpumap_or_pass` at [lib.rs:589](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-xdp/src/lib.rs:589).
- A session miss checks `is_local_destination` and returns `cpumap_or_pass` at [lib.rs:621](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-xdp/src/lib.rs:621).
- `cpumap_or_pass` is cpumap redirect or `XDP_PASS` at [lib.rs:1139](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-xdp/src/lib.rs:1139), and the cpumap has no attached program, so packets enter the kernel at [maps_sync.go:219](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/dataplane/userspace/maps_sync.go:219).

“Never reaches userspace” is too absolute: a session-map `REDIRECT` hit falls through to XSK before any local-destination check at [lib.rs:586](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-xdp/src/lib.rs:586). That exceptional path does not collapse the premise—the ordinary miss still bypasses userspace, so kernel enforcement remains necessary.

2. AVAILABILITY — CONFIRMED-SOUND

The fail-closed direction-(a) argument is correct:

- Missing/not-ready binding and heartbeat failure pass only traffic still recognized by `is_degraded_local_or_control` at [lib.rs:465](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-xdp/src/lib.rs:465) and [lib.rs:1035](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-xdp/src/lib.rs:1035).
- Withholding the address from `USERSPACE_LOCAL` removes that recognition, causing `drop_degraded_transit`.
- `drop_degraded_transit` always returns `XDP_DROP`, regardless of strict mode, at [lib.rs:1064](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-xdp/src/lib.rs:1064).
- XSK redirect failure is also an unconditional drop at [lib.rs:724](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-xdp/src/lib.rs:724).

Kernel nft is AF_XDP-helper-independent once loaded, while preserving the current degraded local-to-kernel path. It still depends on the shim/local-address map and kernel networking, so “helper-independent” should not be stated as dependency-free.

3. OVER-/UNDER-DENY — FLAW

The “whole match” gate is actually per deny term, while Junos-host behavior is an ordered policy program.

- Exact policies are first-match terminating, followed by `from-zone any`, then globals at [policymatch.go:982](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/policymatch/policymatch.go:982) and [policymatch.go:1004](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/policymatch/policymatch.go:1004).
- The plan collects only deny/reject policies at [plan.md:209](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/docs/research/4146-junos-host-direct-deny/plan.md:209) while explicitly deferring permits at [plan.md:323](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/docs/research/4146-junos-host-direct-deny/plan.md:323).
- The existing Rust test proves an exact permit shadows a global deny at [policy_tests.rs:5565](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/policy_tests.rs:5565).

Thus `permit admin; deny all` becomes only `deny all` in nft. This can lock out expressly permitted management traffic.

Other omitted semantics:

- `DestinationAddresses` and `DestinationAddressExcluded` exist at [types_security.go:392](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/config/types_security.go:392) and are enforced at [policymatch.go:1210](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/policymatch/policymatch.go:1210). The plan instead widens every deny to all local addresses in the view.
- Global `FromZones` is an ingress predicate, enforced at [policymatch.go:1018](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/policymatch/policymatch.go:1018), but the plan scopes globals to every host address.
- `from-zone any to-zone junos-host` has no `BuildZoneHostInboundViews` entry named `any`, so the proposed builder has no defined scope for a supported runtime tier.
- `Application.SourcePort` exists at [types_security.go:1088](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/config/types_security.go:1088) and is enforced at [policymatch.go:1605](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/policymatch/policymatch.go:1605). The builder instructions retain only protocol/destination port; `SourcePort != ""` must be explicitly emitted or rejected.
- Cross-family excluded-address behavior is special at [policymatch.go:1282](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/policymatch/policymatch.go:1282); simply splitting an excluded set by family can under-deny the family absent from that set.
- Application lists/sets are ORs and may require multiple nft rules; the singular `L4Match` design does not define this expansion.

The live scheduler exclusion is correct, but it does not repair these larger holes.

4. FEED STALENESS — CONFIRMED-SOUND, conditionally

The runtime overlay premise is correct. Feed prefixes are merged during token resolution at [policymatch.go:1306](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/policymatch/policymatch.go:1306), recursively through address sets at [policymatch.go:1401](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/policymatch/policymatch.go:1401), including a name that is simultaneously static and feed-backed at [policies_addrbook.go:361](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/dataplane/userspace/policies_addrbook.go:361).

R2 now correctly requires recursive feed-tainting. Implementation must inspect every node in the address closure against `DynamicAddress.AddressBindings`, including same-name static+feed objects; resolving with an empty overlay alone cannot detect those cases.

Feed-backed nft rules are not inherently impossible—the feed callback already invokes full `applyConfig` at [daemon_run.go:462](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/daemon/daemon_run.go:462)—but excluding them is the simpler safe choice. Tests must cover direct feed, nested feed, and same-name static+feed cases.

5. SCOPING — FLAW

`daddr` is not ingress-zone scope.

`BuildZoneHostInboundViews` associates an address with the zone owning its destination interface at [zones_host_inbound.go:188](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/dataplane/userspace/zones_host_inbound.go:188). Junos-host policy instead keys on the packet’s logical ingress interface/zone; the Rust path explicitly resolves that ingress at [poll_descriptor/mod.rs:2204](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2204).

This creates both directions of failure:

- A packet entering WAN but addressed to a LAN-owned local IP evades the WAN junos-host deny: under-deny.
- A packet entering LAN but addressed to a WAN-owned local IP incorrectly hits the WAN deny: over-deny.

#3718 does not prevent either case. It only rejects duplicate local addresses having different coarse host-inbound service signatures and explicitly allows identical signatures at [dup_host_local_address.go:43](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/config/dup_host_local_address.go:43). It neither examines junos-host policies nor rejects asymmetric arrival to a uniquely assigned local IP; that same file calls ingress-interface matching the semantically correct model at [dup_host_local_address.go:32](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/config/dup_host_local_address.go:32).

R2’s “bounded to the explicitly named bad source” defense is also false because the plan makes `source-address any` and `source-address-excluded` representable at [plan.md:280](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/docs/research/4146-junos-host-direct-deny/plan.md:280). This needs `iifname`/ingress-zone scoping, not documentation of the wrong verdict.

6. ORDERING — FLAW

Three independent ordering problems exist.

First, the plan reverses the implemented coarse/fine order. Rust explicitly says host-inbound admission runs before junos-host policy at [policy.rs:2905](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/policy.rs:2905); the miss path performs the coarse gate at [poll_descriptor/mod.rs:2182](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2182), then fine policy at [poll_descriptor/mod.rs:2285](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2285). Emitting fine rejects before service admission means a service that should receive a silent coarse drop can instead elicit a TCP RST/ICMP reject and policy counter.

Second, unconditional `ct state established,related accept` at [daemon_nft.go:574](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/daemon/daemon_nft.go:574) does let a denied source ride a pre-existing inbound connection, and `related` can admit additional related traffic. A source denied from the first packet cannot manufacture an established state, but r2’s documented survival differs from Rust, which re-evaluates junos-host policy on every LocalDelivery hit and tears down tightened sessions at [poll_descriptor/mod.rs:1291](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1291). Preserve firewall-originated reply-direction state before the deny; do not exempt all established original-direction inbound traffic without an explicit parity decision.

Third, PMTUD/error accepts are only a coarse-gate exemption in Rust at [host_inbound.rs:418](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/afxdp/forwarding/host_inbound.rs:418); fine junos-host policy runs afterward. Making their kernel accept terminal before an `application any` deny under-enforces that deny. ESP/AH bypass is consistent with the earlier Rust IPsec stage, but PMTUD is not.

7. SSOT — CONFIRMED-SOUND in principle

Kernel-primary plus Rust-secondary enforcement already exists at [daemon_nft.go:216](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/daemon/daemon_nft.go:216) and [zones_host_inbound.go:11](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/dataplane/userspace/zones_host_inbound.go:11). Adding a second renderer from compiled config is not inherently a second source of truth.

The #1319 citation is misplaced: that “two-SSOT split” concerns operational cmdtree versus config-mode schema at [architecture.md:109](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/docs/architecture.md:109), not enforcement engines. Also, sharing config alone does not prove semantic agreement; the failures above demonstrate why a shared ordered IR plus cross-language parity fixtures are required.

8. REMAINDER DECISION — FLAW AS JUSTIFIED; (ii) IS CONDITIONALLY DEFENSIBLE

Option (iii) is indefensible because it preserves the bug. Option (ii) remains a reasonable compatibility choice only if “representable” applies to the complete ordered decision program—not individual deny terms—and warning suppression reflects actual rendered coverage.

The strongest case for option (i) is stronger than the plan admits:

- This repository routinely hard-rejects new strict commits while warning on persisted/peer-loaded configurations, as documented at [compiler.go:40](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/config/compiler.go:40) and [compiler_validate_strict_policy.go:163](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/config/compiler_validate_strict_policy.go:163). Therefore strict rejection need not brick upgrades.
- Junos accepts these configurations because it enforces them; accepting without enforcement is not Junos parity.
- A strict-reject/lenient-warning hybrid prevents new false-security configurations while preserving boot compatibility.

No new operator deferral is necessary: retain option (ii), but redefine it around an exactly projectable ordered chain. Calling the warned remainder “Junos-correct” should be removed.

9. MISSED IMPLEMENTATION HAZARDS — FLAW

- Reject lowering is wrong. Faithful behavior needs a TCP-only `reject with tcp reset`, followed by generic ICMPx reject for non-TCP, exactly as implemented at [daemon_nft.go:1274](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/daemon/daemon_nft.go:1274). `hostInboundReject` is only the TCP/113 ident-reset precedent. Plain deny must also account for the ingress zone’s `tcp-rst` behavior.
- Atomic load is not system-level fail-closed. `nft -f` retains the prior table atomically at [daemon_nft.go:21](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/daemon/daemon_nft.go:21), but the new config remains committed/active and is peer-synced despite this nonfatal tail error at [daemon_apply.go:235](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/daemon/daemon_apply.go:235). When adding a deny, the retained old table is less restrictive, not “equal-or-more restrictive.”
- Counter requirements contradict themselves. A scope/family counter may have multiple rule references, and faithful reject alone produces two references; current code already supports one declaration with multiple references at [daemon_nft.go:509](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/daemon/daemon_nft.go:509). The test must assert every reference is declared, not “referenced once.”
- The proposed aggregate nft metric does not repair ordinary policy hit counters, `then count`, or RT_FLOW policy-deny attribution—the very counters the issue reports as zero. This divergence must be implemented or explicitly documented.
- Warning suppression must consume the same rendered IR. A syntactically representable policy whose scope resolves only to lifeline or no addresses emits no rule and must continue warning.
- RETH/static/live/DHCP address coverage is sound at [zones_host_inbound.go:42](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/dataplane/userspace/zones_host_inbound.go:42), and VRRP/RETH VIP coverage is present at [zones_host_inbound.go:211](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/pkg/dataplane/userspace/zones_host_inbound.go:211), but the test plan needs explicit active/backup RETH/VIP cases.
- The early-return guard should key on actually emitted, nonempty scoped rules. Every configured zone already produces a view; an addressless/lifeline-only deny cannot safely justify creating a table.
- Missing tests include earlier-permit/later-deny, exact-permit/global-deny, from-any, scoped global `FromZones`, destination address/exclusion, source-port applications, cross-family exclusions, an unrepresentable earlier policy blocking later projection, PMTUD, pre-existing conntrack, and coarse-denied `reject`.

Single most important required change: replace independent deny-term emission with an ingress-scoped, coarse-admission-gated, ordered junos-host policy subchain that represents permit termination and stops safely at unrepresentable decisions.

Justification: The kernel nft locus is correct and preserves helper-crash availability, so direction (b) is salvageable. The current deny-only, daddr-scoped projection nevertheless changes first-match and ingress-zone semantics, allowing both management lockout and security under-enforcement.

PLAN-REVISE

Codex session ID: 019f4848-b523-70d0-8951-ce7b89ac8b4b
Resume in Codex: codex resume 019f4848-b523-70d0-8951-ce7b89ac8b4b
