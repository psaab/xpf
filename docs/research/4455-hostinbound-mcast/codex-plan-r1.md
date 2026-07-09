# Codex hostile plan-review r1 (#4455 HI-1)

Task: task-mrdrhq8h-lift14  |  Verdict: PLAN-REVISE (with strong PLAN-KILL case)

```
PLAN-REVISE

1. Kernel-only enforcement is not proven. Direct multicast does hit `should_fallback_early`, but native-GRE inner multicast does not: `userspace-xdp/src/lib.rs:646` classifies GRE inner, `:767`/`:905` parse inner v4/v6, and only session/DNAT/local maps are checked before returning `0` at `:857`/`:989`; then the packet redirects to XSK at `:724`. The plan’s F1/§5.4 claim that multicast “never reaches the XSK” is therefore too broad (`docs/research/4455-hostinbound-mcast/plan.md:40`, `:273`). Required change: either explicitly exclude native-GRE inner multicast from HI-1 with tests proving current behavior, or add Rust-side destination-group admission for the decap path.

2. The VRRP safety argument is overstated. AF_PACKET is real (`pkg/vrrp/manager.go:874`, `:890`; `pkg/vrrp/instance.go:1380`), and that path should see L2 frames before IP input. But the code also has raw IPv4 and IPv6 fallback paths: `ip4:112` opens and joins 224.0.0.18 at `pkg/vrrp/manager.go:799` and `:834`, fallback `receiver()` starts when `afPacketFD < 0` at `pkg/vrrp/instance.go:1029`, and IPv6 fallback uses `ip6:112` at `pkg/vrrp/manager.go:1033`/`pkg/vrrp/instance.go:1268`. The plan only caveats IPv6 (`plan.md:56`). Required change: treat both v4 and v6 raw fallback as nft-input-exposed, and add forced-AF_PACKET-failure validation.

3. Opt-in-off-by-default avoids upgrade breakage, not enable-time breakage. xpf renders FRR OSPF/OSPFv3/RIP config at `pkg/frr/policy_render.go:507`, `:612`, and `:998`; those daemons are normal kernel consumers. Enabling enforcement with missing zone tokens will drop hellos exactly as the plan admits (`plan.md:59`, `:341`). Required change: strict commit on enable must cross-check managed OSPF/OSPFv3/RIP interfaces against zone/per-interface host-inbound protocol tokens, or the migration story remains unsafe. PIM must be called out as unmanaged/missing today (`docs/feature-gaps.md:460`), so external pimd cannot be auto-protected.

4. The proposed `iifname` source is wrong for multicast. `ZoneHostInboundView.Interfaces` is explicitly “informational/test only” and address-scoped (`pkg/dataplane/userspace/zones_host_inbound.go:28`), groups are created lazily on first address (`:97`), and interfaces are only added while iterating addresses (`:199`). Addressless/DHCP-pending/routing-only zone interfaces can therefore get no multicast `iifname` coverage. Required change: build multicast interface sets from zone/interface membership and effective host-inbound overrides, independent of local address presence.

5. RETH resolution is internally contradictory. The plan says RETH multicast arrives on stable `reth` netdevs (`plan.md:241`) and test plan expects “RETH -> reth netdev” (`:412`), but the existing resolver maps `reth0` to the local physical member (`pkg/config/types.go:98`, `:146`, `:178`; tests at `pkg/config/types_test.go:214`). `snapshotLinuxName` mirrors that physical mapping (`pkg/dataplane/userspace/interfaces.go:410`, `:424`). Required change: verify actual nft `iifname` on the loss cluster and align the resolver/tests; do not assert reth names while reusing a physical-member resolver.

6. “Unresolved” cannot mean “string returned.” `ResolveKernelIfName` falls back to a guessed slash-to-dash name for malformed or absent units (`pkg/config/types.go:208`, `:233`). That can silently install rules on a non-existent or wrong interface. Required change: after name translation, validate against live netlink/snapshot netdevs; unresolved must log/gauge and skip drops.

7. The multicast catalog/table is incomplete relative to the known host-inbound protocol universe. `rsvp`, `pgm`, and `sap` are known IP routing-control tokens (`pkg/config/host_inbound_tokens.go:119`) and `protocols all` expands over all non-L2 tokens (`:164`), with concrete matches at `:454`, `:456`, and `:458`; the plan table omits them (`plan.md:297`). Required change: either add their multicast treatment or explicitly exclude them with a defensible reason and document the remaining packet-wide gap.

8. MLD/shared-group handling is mostly correct, but keep it narrow. Current nft global accepts ND only (`pkg/daemon/daemon_nft.go:609`) and Rust mirrors ND/error only (`userspace-dp/src/afxdp/forwarding/host_inbound.rs:461`); the plan avoids broad `ff00::/8` drops (`plan.md:267`). Required change: add a negative test proving ICMPv6 130/131/132/143 is not matched by any proposed drop.

Strong PLAN-KILL case: after fixing the above, this still remains opt-in, protects mainly already-compliant operators, relies on fragile kernel netdev attribution, and touches HA-critical multicast. If native-GRE and resolver correctness cannot be nailed down with tests, keep the shipped advisory and kill enforcement.
```
