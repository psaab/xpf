# #1378 Policy Scheduler Live Evidence

Captured on the isolated `loss` userspace HA cluster from:

- worktree: `/tmp/xpf-b-1378-live-evidence`
- branch: `codex/b-1378-live-evidence`
- commit: `7465b2fdc820606af79b0896260ed90caf2bb39e`
- cluster env: `test/incus/loss-userspace-cluster.env`

Validator command:

```bash
python3 test/incus/policy_scheduler_validate.py \
  docs/pr/1373-retire-ebpf-dataplane/evidence-1378-policy-scheduler-live-20260519 \
  --rule-id 'lan->wan/scheduled-allow'
```

Validator result: `PASS`.

Counter summary for `lan->wan/scheduled-allow`:

| Phase | Packets | Bytes |
|---|---:|---:|
| active | 5 | 490 |
| rebuild | 5 | 490 |
| inactive | 5 | 490 |
| failover | 20 | 1876 |

The active, rebuild, inactive, and failover status files all show userspace
forwarding armed with snapshot protocol version 2 and `xdp_userspace_p`
attached as the entry program. `failover-status.json` was captured from
`loss:xpf-userspace-fw1` after RG1/RG2 moved to node1 and post-failover
traffic traversed the scheduled policy.

`missing-scheduler-commit.txt` captures a `commit check` rejection for a
policy referencing undefined scheduler `workhours`; the candidate was rolled
back and never committed.

The lab was restored after capture. `restore-final-cluster-status.txt` shows
node0 primary for RG0/RG1/RG2, and `restore-final-configuration.txt` contains
no scheduler or `scheduled-allow` policy residue.
