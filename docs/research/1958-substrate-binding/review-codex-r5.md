# Codex — hostile plan-review round 5 (verbatim)

Branch `research/1958-refresh` @ `1406f13f3`, rebased onto origin/master
`4e6fc2f2e`. Verifying the v5 fold of the r4 catches (container substrate +
stale base).

---

VERDICT: PLAN-READY (defer judgment sound, fold adequate)

1. CLEAN: `git -C /home/ps/git/bpfrx/.claude/worktrees/1958-research-refresh merge-base --is-ancestor 4e6fc2f2e 1406f13f3` returned exit code `0`. The plan also states the rebase fix at `docs/research/1958-substrate-binding/plan.md:54-58`.

2. CLEAN: I read the full 864-line `plan.md`; the v5 fold is `plan.md:10-109`, v4 is explicitly marked superseded at `plan.md:113`, and the inherited plan runs through `plan.md:864`. v5 says it supersedes v4 and rewrites the materially wrong rationale at `plan.md:12-16`.

3. CLEAN: `Makefile:167` includes `test-ct` in `.PHONY`, and `Makefile:177-178` maps it to `./test/incus/setup.sh create-ct`. `test/incus/setup.sh:43` defines `CT_PROFILE="xpf-container"`, `setup.sh:283-317` defines a privileged container with `eth0..eth4`, and `setup.sh:511-520` launches it; `cluster-setup.sh` does not contain `xpf-container`, but separately creates a LAN test container at `cluster-setup.sh:326-327` and `cluster-setup.sh:528-542`. `enumerateAndRenameInterfaces` returns nil when `len(nics)==0` at `pkg/daemon/linksetup.go:66-73`, while `enumeratePCINICs` skips non-PCI devices via `/sys/class/net/<name>/device` and empty PCI extraction at `linksetup.go:167-187`; `pkg/devicemap/devicemap.go:270-277` has the same non-PCI skip. The bootstrap lifeline is PCI-gated at `pkg/daemon/bootstrap.go:609-625` and only writes after that succeeds at `bootstrap.go:727-730`; unmanaged interfaces become `Unmanaged` at `pkg/dataplane/compiler_iface.go:1190-1195` and networkd emits `ActivationPolicy=always-down` at `pkg/networkd/networkd.go:436-438`. `test/incus/xpf-test.conf:1-60` uses `fxp0` and `ge-0/0/0..4`; `rg "eth[0-9]" test/incus/xpf-test.conf` returned exit code `1`.

4. CLEAN: The corrected defer rationale is sound on the requested lockout axis. The standalone container harness's "ssh" command is `incus exec` at `test/incus/setup.sh:654-658`, its package install list at `setup.sh:423-428` does not include `openssh-server`, and the deployer's supported provisioning surfaces are Incus VM/libvirt at `scripts/deploy/xpf-deploy.py:36`, `xpf-deploy.py:314`, `xpf-deploy.py:358-365`, and `xpf-deploy.py:1229`. The image bake exports qcow2 plus Incus VM metadata at `scripts/image/bake.py:4-8`, purges cloud-init at `bake.py:316-319`, and the package is amd64-only at `debian/control:10-11`; exact VMBus/XenBus/Azure/IMDS/Amazon driver/provisioning search returned no matches, while `aws`/`ec2` hits were only publish/test variable lines at `scripts/dist/publish.py:27`, `scripts/dist/publish.py:152`, and `pkg/flowexport/exporter_test.go:602-606`.

5. CLEAN: I found no new v5 defect. The old false v4 "no concrete consumer/no CI substrate" text remains only in the historical block, and v5 explicitly supersedes it at `plan.md:12-16` and `plan.md:113`; v5 then drops that argument at `plan.md:78-82`. The apparent PLAN-READY wording later in the inherited body at `plan.md:262-278` is reconciled by v5's current disposition: net-new B/C are PLAN-DEFER while architecture remains PLAN-READY as design-of-record at `plan.md:103-109`.
