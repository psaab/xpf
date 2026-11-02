"""Failure-direction tests for scripts/host-mutation-census.py."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
CENSUS = REPO / "scripts/host-mutation-census.py"
PACKAGES = (
    "pkg/daemon",
    "pkg/dataplane",
    "pkg/dataplane/userspace",
    "pkg/flowexport",
    "pkg/lldp",
    "pkg/nftables",
    "pkg/ra",
    "pkg/routing",
    "pkg/snmp",
)


class HostMutationCensusTest(unittest.TestCase):
    def setUp(self):
        scratch = os.environ.get("TMPDIR", "/var/worktrees/.cache/tmpdir")
        Path(scratch).mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="host-mutation-census-", dir=scratch)
        self.root = Path(self.temp.name)
        for package in PACKAGES:
            directory = self.root / package
            directory.mkdir(parents=True)
            (directory / "guard_test.go").write_text(
                "package fixture\nfunc TestMain(m *testing.M) { testguard.ExitIfUnsafe(); os.Exit(m.Run()) }\n",
                encoding="utf-8",
            )
        (self.root / "scripts").mkdir()
        (self.root / "test").mkdir()
        self.rows = [
            "pkg/daemon/netlink_test.go\tnetlink\tprivate-net+mount\t"
            "package-TestMain:testguard.ExitIfUnsafe;testguard-run",
            "pkg/dataplane/nft_test.go\tnft\tprivate-net+mount\t"
            "package-TestMain:testguard.ExitIfUnsafe;testguard-run",
            "pkg/dataplane/userspace/bpf_test.go\tbpf\tprivate-net+mount\t"
            "package-TestMain:testguard.ExitIfUnsafe;testguard-run;vm-test-root-for-privileged-map-cells",
        ]
        (self.root / "pkg/daemon/netlink_test.go").write_text(
            "package fixture\nfunc test() { netlink.LinkAdd(link) }\n", encoding="utf-8"
        )
        (self.root / "pkg/dataplane/nft_test.go").write_text(
            "package fixture\nfunc test() { xnft.NewNetlinkInstaller() }\n", encoding="utf-8"
        )
        (self.root / "pkg/dataplane/userspace/bpf_test.go").write_text(
            "package fixture\nfunc test() { ebpf.NewMap(spec) }\n", encoding="utf-8"
        )
        self.write_registry()
        (self.root / "scripts/host-mutation-census.floors").write_text(
            "netlink\t1\nnft\t1\nbpf\t1\n", encoding="utf-8"
        )

    def tearDown(self):
        self.temp.cleanup()

    def write_registry(self, rows=None):
        rows = self.rows if rows is None else rows
        (self.root / "test/host-mutation-census.tsv").write_text(
            "# source\tclass\tisolation\tproof\n" + "\n".join(rows) + "\n",
            encoding="utf-8",
        )

    def run_census(self):
        return subprocess.run(
            [sys.executable, str(CENSUS), "--root", str(self.root)],
            cwd=REPO,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_complete_registry_passes(self):
        result = self.run_census()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bidirectional floors PASS", result.stdout)

    def test_new_candidate_requires_registry_row(self):
        (self.root / "pkg/flowexport/new_mutation_test.go").write_text(
            "package fixture\nfunc test() { netlink.RouteAdd(route) }\n", encoding="utf-8"
        )
        result = self.run_census()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unregistered host-mutation test source", result.stderr)

    def test_stale_registry_row_is_rejected(self):
        self.write_registry(self.rows + [
            "pkg/ra/stale_test.go\tnetlink\tprivate-net+mount\t"
            "package-TestMain:testguard.ExitIfUnsafe;testguard-run"
        ])
        result = self.run_census()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stale/non-mutating registry row", result.stderr)

    def test_class_floor_cannot_shrink(self):
        (self.root / "scripts/host-mutation-census.floors").write_text(
            "netlink\t2\nnft\t1\nbpf\t1\n", encoding="utf-8"
        )
        result = self.run_census()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("netlink census below floor", result.stderr)

    def test_missing_package_guard_is_rejected(self):
        guard = self.root / "pkg/nftables/guard_test.go"
        guard.write_text("package fixture\nfunc TestMain(m *testing.M) { os.Exit(m.Run()) }\n", encoding="utf-8")
        result = self.run_census()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TestMain must call testguard.ExitIfUnsafe", result.stderr)


if __name__ == "__main__":
    unittest.main()
