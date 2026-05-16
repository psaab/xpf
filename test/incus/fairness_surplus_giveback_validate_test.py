import unittest

from fairness_surplus_giveback_validate import validate


def _artifact(**overrides):
    base = {
        "root_cap_mbps": 25000,
        "peer_guarantee_mbps": 10000,
        "handback_window_sec": 3.0,
        "phases": [
            {"name": "borrow_alone", "throughput_mbps": {"borrower": 18000, "peer": 0}},
            {"name": "peer_demand", "throughput_mbps": {"borrower": 16000, "peer": 7000}},
            {
                "name": "peer_steady",
                "throughput_mbps": {"borrower": 9000, "peer": 9800},
                "cos_admission_drops": {"peer": 0},
            },
            {"name": "peer_idle_reclaim", "throughput_mbps": {"borrower": 17000, "peer": 0}},
        ],
    }
    base.update(overrides)
    return base


def _validate(artifact):
    return validate(
        artifact,
        min_peer_guarantee_ratio=0.95,
        max_handback_sec=5.0,
        max_borrower_demand_ratio=0.90,
        min_reclaim_ratio=1.10,
        root_cap_tolerance_ratio=0.02,
        max_peer_steady_drops=0,
    )


class SurplusGivebackValidateTests(unittest.TestCase):
    def test_passes_contract(self):
        verdict = _validate(_artifact())
        self.assertEqual(verdict["verdict"], "PASS")
        self.assertEqual(verdict["failure_reasons"], [])

    def test_fails_peer_below_guarantee(self):
        artifact = _artifact()
        artifact["phases"][2]["throughput_mbps"]["peer"] = 9400
        verdict = _validate(artifact)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("below" in r for r in verdict["failure_reasons"]))

    def test_fails_slow_handback(self):
        verdict = _validate(_artifact(handback_window_sec=6.5))
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("handback" in r for r in verdict["failure_reasons"]))

    def test_fails_root_cap_overshoot(self):
        artifact = _artifact()
        artifact["phases"][1]["throughput_mbps"] = {"borrower": 23000, "peer": 4000}
        verdict = _validate(artifact)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("root cap" in r for r in verdict["failure_reasons"]))


if __name__ == "__main__":
    unittest.main()
