# Codex — hostile plan review r1 — #3620 intrazone default

Dispatched via `codex:codex-rescue` (fresh task `task-mr1rvyi1-jgmogm`) after the
first companion job `task-mr1rslvt-ra3ovj` dropped from the registry
(fetch-by-id "No job found" — documented Codex infra-drop). Read-only; no
mutation, no tests.

---

**Verdict: PLAN-KILL-CONFIRMED**

I tried to break the crux and did not find a valid SRX/vSRX implicit intrazone
permit. The plan's Junos resolution is sound: mainline SRX policy lookup applies
to same-zone transit, and unmatched traffic falls to `security policies
default-policy`, whose documented default is `deny-all`.

Findings:

- Juniper's Security Policies Overview explicitly says policy lookup occurs when
  traffic passes "between two interfaces bound to the same zone," and that a
  permitting policy must exist.
  https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/concept/policy-overview.html
- Juniper's `default-policy` reference says the default security policy handles
  packets that do not match user-defined policy, and `deny-all` is the default.
  https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-default-policy.html
- The `default-permit` cited by the old review is not a runtime default. The
  local sample first says `Default policy: deny-all`, then shows `From zone:
  trust, To zone: trust` with named policy `default-permit`, `Index: 4`, `Action:
  permit`: docs/junos-cli-reference.md:213. That is a configured policy row, not
  an implicit tier.
- The factory-default exception does not flip the verdict. Juniper calls it a
  "factory-default security policy" (shipped configuration, not the policy
  engine's unmatched runtime default).
- Packet-based forwarding is the only real caveat worth documenting: if traffic
  is explicitly marked packet-mode, Juniper says flow-based security features are
  bypassed.
  https://www.juniper.net/documentation/us/en/software/junos/flow-packet-processing/topics/topic-map/security-packet-based-forwarding.html
  That is not an implicit intrazone permit; it is explicit stateless forwarding
  outside this tier question.

Code claims hold against both the current worktree and `bd2443c5e`:

- Rust has no `from_id == to_id` branch. `evaluate_policy_result_l3_aware` checks
  exact zone pair, wildcard tiers, global, then default under only
  `from_id != 0 && to_id != 0`: userspace-dp/src/policy.rs:2604, :2629, :2766.
- `PolicyState` has a single `default_action`, defaulting to deny:
  userspace-dp/src/policy.rs:1701, :1774.
- Go mirror also has no same-zone branch. Tier 1 exact matching is ordinary
  `FromZone == q.FromZone && ToZone == q.ToZone`; Tier 5 returns the configured
  default: pkg/policymatch/policymatch.go:369, :443.
- Show/counter surfaces do not synthesize an intrazone row; they walk configured
  zone-pair/global policies and use one default-policy sentinel/counter:
  pkg/dataplane/userspace/policies.go:243, userspace-dp/src/policy.rs:686.

Disposition is correct. Building Option B would permit unmatched same-zone
traffic that SRX default-deny would drop, so the "security regression" framing is
fair. Option A′ docs clarification is warranted to prevent re-filing the same
misconception, but I would not block closure on it.
