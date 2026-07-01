I will start by listing the current permissions to see if I already have access to the repository directory.
I will request read permission for the research worktree at `/home/ps/git/bpfrx/.claude/worktrees/3620-research` so I can examine the plan document and code files.
I will read the plan document at `/home/ps/git/bpfrx/.claude/worktrees/3620-research/docs/research/3620-intrazone/plan.md`.
I will perform a web search to verify the behavior of mainline Junos SRX/vSRX regarding intrazone traffic, specifically looking for any cases where it might implicitly permit unmatched intrazone traffic.
I will search for the behavior of Junos SRX in packet-based mode to see if it implicitly permits unmatched intrazone traffic in that mode.
I will search for the definition of `evaluate_policy_result_l3_aware` in the codebase to find the exact file and line numbers.
I will view the code around `evaluate_policy_result_l3_aware` in `/home/ps/git/bpfrx/.claude/worktrees/3620-research/userspace-dp/src/policy.rs` to verify the policy evaluation flow.
I will perform a grep search to find files matching `policymatch.go` to locate its exact path.
I will view the file `policymatch.go` to examine the Go policy matching simulator's implementation and verify that it matches the description in the plan document.
I will search for `walkPolicyRuleSlots` to locate the exact file and lines.
I will read `walkPolicyRuleSlots` in `/home/ps/git/bpfrx/.claude/worktrees/3620-research/pkg/dataplane/userspace/policies.go` around line 243.
I will read `docs/userspace-dataplane-architecture.md` around lines 610-670 to confirm that the architecture documentation matches the plan's description.
I will read `docs/junos-cli-reference.md` around lines 210-230 to verify the CLI reference show security policies sample content and how it's structured.
I will perform a web search to check how same-interface hairpinning or intra-interface traffic is handled by Junos SRX security policies.
I will search the web to confirm if the `intrazone-block` option or equivalent exists on Junos SRX, or if it was entirely a ScreenOS construct.
I will search for occurrences of `#3620` in the repository's docs directory to understand its history and check for any related or duplicate issues.
I will read the hostile plan review file at `/home/ps/git/bpfrx/.claude/worktrees/3620-research/docs/research/3620-intrazone/claude-smr-plan-r1.md` to see if there is any pre-existing review or reference that I should take into account.
I will search for any other files in the `docs/research/3620-intrazone` directory to ensure I haven't missed any other context or drafts.
## Verdict: `PLAN-KILL-CONFIRMED` (Premise False, Current Behavior Correct)

---

### 1. The Premise (Junos Semantics Resolution)

The plan's Junos-semantics resolution is **entirely correct**. Mainline Junos SRX/vSRX (unlike legacy ScreenOS) subjects intrazone (same-zone) traffic to security policies and blocks unmatched traffic by default. 

*   **Runtime Default Deny:** The `default-policy` statement defaults to "Deny all traffic. Packets are dropped. This is the default." (Juniper Reference: `security-edit-default-policy.html`). It governs any packet that does not match a user-defined policy.
*   **Intrazone policy evaluation:** Juniper’s *Security Policies Overview* explicitly states: 
    > "Every time a packet attempts to pass from one zone to another **or between two interfaces bound to the same zone**, the device checks for a policy that permits such traffic."
    Therefore, unmatched intrazone traffic falls through to the `default-policy` (deny-all) and is dropped.
*   **The "Default-Permit" Illusion:** The review's claim of an implicit permit relies on [docs/junos-cli-reference.md:L213-L227](file:///home/ps/git/bpfrx/.claude/worktrees/3620-research/docs/junos-cli-reference.md#L213-L227). However, as highlighted in the plan:
    *   Line 213 shows `Default policy: deny-all`.
    *   Line 218 shows a policy named `default-permit` with `Index: 4` and `Sequence number: 1`. This is a user-configured (or branch-SRX factory-default shipped) policy applied from `zone: trust` to `zone: trust`. It is **not** a hardcoded runtime fallback.
*   **Corner Cases Probed:**
    *   *Same-Interface Hairpin / U-Turn:* Junos SRX still evaluates this flow against security policies (`from-zone <zone>` to `to-zone <zone>`). If no policy matches, it drops.
    *   *Packet-Based vs Flow-Based Mode:* In packet-based mode, the SRX acts as a traditional router, meaning all flow-based security policy subsystems are bypassed globally (not just for intrazone traffic). It does not represent an intrazone-permit tier within the security system.
    *   *Legacy ScreenOS:* ScreenOS had a per-zone `intrazone-block` option that defaulted to unblocked, permitting intrazone traffic implicitly. Mainline Junos SRX completely removed this construct; no such knob exists.

---

### 2. The Code Claims

The plan's assertions regarding the codebase are completely accurate:

1.  **Rust Dataplane:** In [userspace-dp/src/policy.rs](file:///home/ps/git/bpfrx/.claude/worktrees/3620-research/userspace-dp/src/policy.rs), the function [evaluate_policy_result_l3_aware](file:///home/ps/git/bpfrx/.claude/worktrees/3620-research/userspace-dp/src/policy.rs#L2604-L2795) contains no `from_id == to_id` check or bypass branch. Same-zone traffic goes through the exact same 5-tier evaluation (exact zone-pair $\rightarrow$ single-wildcard $\rightarrow$ both-any $\rightarrow$ junos-global $\rightarrow$ default fallback). If unmatched, it falls through to line 2768: `action: state.default_action` (which defaults to `PolicyAction::Deny`).
2.  **Go Simulator:** In [pkg/policymatch/policymatch.go](file:///home/ps/git/bpfrx/.claude/worktrees/3620-research/pkg/policymatch/policymatch.go), the function [Match](file:///home/ps/git/bpfrx/.claude/worktrees/3620-research/pkg/policymatch/policymatch.go#L351-L445) performs standard checks. Tier 5 (line 444) returns the default policy unconditionally for any unmatched traffic:
    `return Result{DefaultUsed: true, Action: cfg.Security.DefaultPolicy}`
    There is no same-zone branching here.
3.  **Show Surfaces:** In [pkg/dataplane/userspace/policies.go](file:///home/ps/git/bpfrx/.claude/worktrees/3620-research/pkg/dataplane/userspace/policies.go), [walkPolicyRuleSlots](file:///home/ps/git/bpfrx/.claude/worktrees/3620-research/pkg/dataplane/userspace/policies.go#L243-L285) iterates strictly over user-configured zone-pair policies and global policies. It does not synthesize or output any default-permit rules.
4.  **Architecture Docs:** In [docs/userspace-dataplane-architecture.md:L610-L667](file:///home/ps/git/bpfrx/.claude/worktrees/3620-research/docs/userspace-dataplane-architecture.md#L610-L667), the 5-tier lookup model is described with no implicit intrazone tier, confirming that unmatched same-zone traffic falls straight to the default action (deny).

---

### 3. The Disposition

`PLAN-KILL` is the correct disposition. 
*   **Security Regression (Option B):** Implementing Option B would add an implicit runtime permit tier for intrazone traffic when unmatched. Because mainline SRX drops unmatched intrazone traffic under its default `deny-all` policy, implementing Option B would introduce a silent security regression where xpf permits same-zone traffic that a real SRX (and the operator's default-deny configuration) would block.
*   **ScreenOS compatibility mode (Option C):** Deferred. There is no config knob `intrazone-block` on Junos SRX. Implementing one would be a non-standard compatibility layer that is out of scope for a vSRX parity issue.
*   **Option A' (Docs Clarification):** Highly recommended but does not gate the closure of this issue. Adding a clarifying note near the `show security policies` sample in [docs/junos-cli-reference.md](file:///home/ps/git/bpfrx/.claude/worktrees/3620-research/docs/junos-cli-reference.md) will prevent future reviewers from raising the same concern.

---

### 4. Gaps and Dedup

No gaps were found. The plan correctly addresses all nuances:
*   **Knobs:** No `intrazone-block` is supported on Junos SRX.
*   **Observability:** Unmatched same-zone traffic is correctly logged using `DEFAULT_POLICY_SENTINEL_ID` (u32::MAX), rendering as `default-policy` in logs, mirroring real SRX behavior.
*   **Dedup:** The issue is distinct from:
    *   `#3042` (operator simulator vs runtime logic mismatches)
    *   `#3065` / `#3363` / `#3057` / `#3534` (general transit default policy logging and counter logic)
    *   `#3611` (the `junos-host` self-zone local-delivery gate)

### Summary of Work
1. Reviewed the research plan `docs/research/3620-intrazone/plan.md`.
2. Verified Junos SRX default policy behavior using authoritative Juniper documentation and community references, confirming that unmatched intrazone traffic is denied by default.
3. Verified the codebase behavior in [userspace-dp/src/policy.rs](file:///home/ps/git/bpfrx/.claude/worktrees/3620-research/userspace-dp/src/policy.rs), [pkg/policymatch/policymatch.go](file:///home/ps/git/bpfrx/.claude/worktrees/3620-research/pkg/policymatch/policymatch.go), and [pkg/dataplane/userspace/policies.go](file:///home/ps/git/bpfrx/.claude/worktrees/3620-research/pkg/dataplane/userspace/policies.go) to confirm the lack of a same-zone exception.
4. Confirmed that building an implicit permit tier would introduce a critical security regression, verifying `PLAN-KILL-CONFIRMED` as the correct disposition.
