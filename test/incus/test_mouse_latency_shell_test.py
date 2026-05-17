import pathlib
import re
import unittest


SCRIPT = pathlib.Path(__file__).with_name("test-mouse-latency.sh").read_text()
MATRIX_SCRIPT = pathlib.Path(__file__).with_name("test-mouse-latency-matrix.sh").read_text()


class MouseLatencyShellTests(unittest.TestCase):
    def test_surplus_fixture_env_is_validated_and_passed_to_apply(self):
        self.assertIn('MOUSE_COS_SURPLUS_SHARING="${MOUSE_COS_SURPLUS_SHARING:-0}"', SCRIPT)
        self.assertIn('MOUSE_COS_SURPLUS_SHARING=1', SCRIPT)
        self.assertIn("MOUSE_COS_SURPLUS_SHARING='$MOUSE_COS_SURPLUS_SHARING' must be boolean", SCRIPT)

        self.assertRegex(
            SCRIPT,
            re.compile(
                r'if \[\[ "\$MOUSE_COS_SURPLUS_SHARING" -eq 1 \]\]; then\s+'
                r'APPLY_COS_FLAGS\+=\(--surplus-sharing\)\s+fi',
                re.MULTILINE,
            ),
        )

    def test_surplus_fixture_choice_is_written_to_manifest(self):
        self.assertIn(
            'MOUSE_CLASS="$MOUSE_CLASS" MOUSE_COS_SURPLUS_SHARING="$MOUSE_COS_SURPLUS_SHARING"',
            SCRIPT,
        )
        self.assertIn('"cos_surplus_sharing": os.environ["MOUSE_COS_SURPLUS_SHARING"] == "1"', SCRIPT)

    def test_matrix_documents_surplus_fixture_knob(self):
        self.assertIn("Set MOUSE_COS_SURPLUS_SHARING=1", MATRIX_SCRIPT)
        self.assertIn("per-rep manifest records the selected fixture bit", MATRIX_SCRIPT)

    def test_settle_budget_and_diagnostics_are_recorded(self):
        self.assertIn('SETTLE_BUDGET="${MOUSE_LATENCY_SETTLE_BUDGET:-20}"', SCRIPT)
        self.assertIn("MOUSE_LATENCY_SETTLE_BUDGET='$SETTLE_BUDGET' must be a positive integer second count", SCRIPT)
        self.assertIn('settle-diagnostics "${OUT_DIR}/iperf3-settle.txt" "$SHAPER_BPS"', SCRIPT)
        self.assertIn('"settle_budget_s": int(os.environ["SETTLE_BUDGET"])', SCRIPT)
        self.assertIn('"cwnd_settle_elapsed_s": int(os.environ["CWND_SETTLE_ELAPSED"])', SCRIPT)
        self.assertIn('CWND_SETTLE_OK="unknown"', SCRIPT)
        self.assertIn('CWND_SETTLE_OK="false"', SCRIPT)
        self.assertIn('settle_ok = None', SCRIPT)
        self.assertIn('"cwnd_settle_ok": settle_ok', SCRIPT)
        self.assertIn('"status": "INVALID"', SCRIPT)
        self.assertIn('write_invalid_manifest "$reason"', SCRIPT)

    def test_runtime_cos_and_settle_cpu_artifacts_are_cleared_and_captured(self):
        for artifact in (
            '"/cwnd-settle.json \\',
            '"/mpstat-settle.txt \\',
            '"/cos-interface-pre.txt \\',
            '"/cos-interface-settle.txt \\',
            '"/cos-interface-post.txt \\',
        ):
            self.assertIn(artifact, SCRIPT)
        self.assertIn("show class-of-service interface", SCRIPT)
        self.assertIn("mpstat 1 ${SETTLE_BUDGET} > /tmp/mpstat-settle-${REP_TAG}.txt", SCRIPT)


if __name__ == "__main__":
    unittest.main()
