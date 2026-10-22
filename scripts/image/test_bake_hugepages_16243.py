#!/usr/bin/env python3
"""Regression tests for the UMEM hugepage provisioning path (#16243).

The code side was already done: UMEM tries MAP_HUGETLB first, reports
`hugepage_backed` per binding, and sizes the pool at 80 x 2 MiB pages per
binding (umem_sizing_contract_tests). The measured rig defect was purely
provisioning: etc/sysctl.d/99-xpf-hugepages.conf existed in the repo but
NO path installed it -- not the bake, not the .deb, not any deploy tool --
so a ring-entries 16384 rig booted with HugePages_Total=0 and reported
`Hugepage-backed bindings: 0/30`.

These tests pin the bake half of the fix: virt_customize must write the
conf, verbatim from the repo file (single source of truth), and the value
must still cover the reference topology at the pinned 80 pages/binding.
"""

from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path
from unittest.mock import patch

_SPEC = importlib.util.spec_from_file_location(
    "bake", Path(__file__).with_name("bake.py")
)
bake = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(bake)

CONF_PATH_PREFIX = "/etc/sysctl.d/99-xpf-hugepages.conf:"


def _hugepages_write(argv):
    return next(
        value for flag, value in zip(argv, argv[1:])
        if flag == "--write" and value.startswith(CONF_PATH_PREFIX)
    )[len(CONF_PATH_PREFIX):]


class BakeHugepagesTests(unittest.TestCase):
    def test_bake_installs_hugepages_conf_verbatim_from_repo(self):
        calls = []
        with patch.object(bake, "run", side_effect=lambda argv: calls.append(argv)):
            bake.virt_customize("appliance.qcow2", "xpf.deb")

        shipped = _hugepages_write(calls[0])
        repo_conf = Path(bake.HUGEPAGES_CONF_PATH).read_text()
        self.assertEqual(
            shipped, repo_conf,
            "bake must ship etc/sysctl.d/99-xpf-hugepages.conf verbatim; "
            "a divergent copy would drift from the operator-edited file",
        )

    def test_shipped_pool_covers_reference_topology(self):
        conf = bake.hugepages_conf()
        m = re.search(r"^vm\.nr_hugepages\s*=\s*(\d+)\s*$", conf, re.M)
        self.assertIsNotNone(m, "conf must set vm.nr_hugepages")
        pages = int(m.group(1))
        # Pinned by umem_sizing_contract_tests: 80 pages per binding at
        # ring-entries 16384; reference topology 3 candidates x 6 queues.
        self.assertGreaterEqual(
            pages, 80 * 18,
            "pool must cover the 18-binding reference topology; "
            "the old one-NIC value (600) is exactly the #16243 failure",
        )

    def test_hugepages_conf_refuses_a_pool_less_file(self):
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = (
                "# no reservation here\n"
            )
            with self.assertRaises(SystemExit):
                bake.hugepages_conf()


if __name__ == "__main__":
    unittest.main()
