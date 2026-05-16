import unittest

from fairness_surplus_giveback_validate import validate


def _artifact(**overrides):
    base = {
        "root_cap_mbps": 25000,
        "borrower_guarantee_mbps": 10000,
        "peer_guarantee_mbps": 10000,
        "handback_window_sec": 3.0,
        "handback_evidence": {"source": "transition_observed", "observed": True},
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
        min_peer_demand_ratio=0.01,
        min_borrower_borrow_ratio=1.05,
        max_handback_sec=5.0,
        max_borrower_demand_ratio=0.90,
        min_reclaim_ratio=1.10,
        min_reclaim_alone_ratio=0.90,
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

    def test_fails_without_auditable_handback_evidence(self):
        artifact = _artifact()
        artifact.pop("handback_evidence")
        verdict = _validate(artifact)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("unaudited scalar" in r for r in verdict["failure_reasons"]))

    def test_accepts_time_domain_handback_samples(self):
        artifact = _artifact()
        artifact.pop("handback_evidence")
        artifact["handback_window_sec"] = 999.0
        artifact["handback_samples"] = [
            {"t_sec": 0.5, "throughput_mbps": {"borrower": 17000, "peer": 1000}},
            {"t_sec": 3.5, "throughput_mbps": {"borrower": 9000, "peer": 9800}},
        ]
        verdict = _validate(artifact)
        self.assertEqual(verdict["verdict"], "PASS")
        self.assertEqual(verdict["metrics"]["handback_source"], "handback_samples")
        self.assertEqual(verdict["metrics"]["handback_window_sec"], 3.5)

    def test_fails_when_time_domain_samples_never_show_handback(self):
        artifact = _artifact()
        artifact.pop("handback_evidence")
        artifact["handback_samples"] = [
            {"t_sec": 0.5, "throughput_mbps": {"borrower": 17000, "peer": 1000}},
            {"t_sec": 3.5, "throughput_mbps": {"borrower": 16000, "peer": 2000}},
        ]
        verdict = _validate(artifact)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("never show" in r for r in verdict["failure_reasons"]))

    def test_fails_when_borrower_never_borrows_surplus(self):
        artifact = _artifact()
        artifact["phases"][0]["throughput_mbps"]["borrower"] = 10000
        verdict = _validate(artifact)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("does not prove surplus borrow" in r for r in verdict["failure_reasons"]))

    def test_fails_when_peer_demand_phase_is_decorative(self):
        artifact = _artifact()
        artifact["phases"][1]["throughput_mbps"]["peer"] = 0
        verdict = _validate(artifact)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("peer demand throughput" in r for r in verdict["failure_reasons"]))

    def test_fails_when_reclaim_not_near_borrow_alone(self):
        artifact = _artifact()
        artifact["phases"][3]["throughput_mbps"]["borrower"] = 9901
        verdict = _validate(artifact)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("not near borrow-alone" in r for r in verdict["failure_reasons"]))

    def test_fails_root_cap_overshoot(self):
        artifact = _artifact()
        artifact["phases"][1]["throughput_mbps"] = {"borrower": 23000, "peer": 4000}
        verdict = _validate(artifact)
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertTrue(any("root cap" in r for r in verdict["failure_reasons"]))


if __name__ == "__main__":
    unittest.main()
