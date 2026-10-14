"""#13070 (D10-15) parity gate: the shared CoS schedule vs the fixture.

The canonical 12-port CoS schedule (port -> queue / forwarding-class /
filter-term / shaper-rate) used to be copy-pasted into eight shell and
Python harnesses; whenever one copy was edited without the others the
harnesses silently measured against a grid the cluster was not running
(D10-08's retired 4-port step1 tables are the canonical example). The fix
single-sources the grid:

- bash: cos-apply-lib.sh's cos_port_to_queue / cos_port_to_class /
  cos_port_to_term / cos_port_to_rate_bps (+ COS_SCHEDULE_PORTS,
  cos_port_is_exact), sourced by every shell consumer;
- Python: cos_fixture_spec.py, which DERIVES its tables by parsing
  cos-iperf-config.set so they cannot drift by construction.

This test is the binding that makes the single source honest. It parses
test/incus/cos-iperf-config.set with its OWN independent parser (not the
module's) and asserts, for EVERY term 0..11 on BOTH port families, that
the bash library and the Python module agree with the fixture. A fixture
edit without the matching library edit reds here.

It also pins the consumer wiring (#8244 pattern): a script that
substitutes a shared value without SOURCING the file that defines it
expands to empty, which is worse than a wrong number and passes every
value assertion — so the source/import lines themselves are asserted.
"""

import pathlib
import re
import shlex
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
FIXTURE = (ROOT / "cos-iperf-config.set").read_text()
LIB = ROOT / "cos-apply-lib.sh"

# --- independent fixture parse (deliberately NOT cos_fixture_spec) ---------

_FC_QUEUE_RE = re.compile(
    r"^set class-of-service forwarding-classes queue (\d+) (\S+)$", re.M
)
_TERM_PORT_RE = re.compile(
    r"^set firewall family inet filter bandwidth-output term (\d+) "
    r"from destination-port (\d+)$",
    re.M,
)
_TERM_CLASS_RE = re.compile(
    r"^set firewall family inet filter bandwidth-output term (\d+) "
    r"then forwarding-class (\S+)$",
    re.M,
)
_SCHED_RATE_RE = re.compile(
    r"^set class-of-service schedulers (\S+) transmit-rate (\S+)$", re.M
)
_SCHED_MAP_RE = re.compile(
    r"^set class-of-service scheduler-maps \S+ forwarding-class (\S+) "
    r"scheduler (\S+)$",
    re.M,
)
_IFACE_SHAPE_RE = re.compile(
    r"^set class-of-service interfaces \S+ unit \d+ shaping-rate (\S+)$", re.M
)


def _junos_rate(token: str) -> int:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([kmgt]?)", token.lower())
    assert m is not None, f"unparseable fixture rate: {token!r}"
    mult = {"": 1, "k": 10**3, "m": 10**6, "g": 10**9, "t": 10**12}[m.group(2)]
    return int(float(m.group(1)) * mult)


def _fixture_grid() -> dict:
    """Port -> {queue, class, term, rate_bps, exact} straight from the .set."""
    queue_by_class = {fc: int(q) for q, fc in _FC_QUEUE_RE.findall(FIXTURE)}
    class_by_term = {t: fc for t, fc in _TERM_CLASS_RE.findall(FIXTURE)}
    sched_by_class = {
        fc: sched for fc, sched in _SCHED_MAP_RE.findall(FIXTURE)
    }
    rate_by_sched = {}
    exact_scheds = set()
    for sched, val in _SCHED_RATE_RE.findall(FIXTURE):
        if val == "exact":
            exact_scheds.add(sched)
        else:
            rate_by_sched[sched] = _junos_rate(val)
    iface_shape = _junos_rate(_IFACE_SHAPE_RE.search(FIXTURE).group(1))

    grid = {}
    for term, port in _TERM_PORT_RE.findall(FIXTURE):
        fc = class_by_term[term]
        sched = sched_by_class[fc]
        exact = sched in exact_scheds
        # Same cap rule the harness family uses: the exact scheduler's
        # transmit-rate for exact classes, the interface shaping-rate for
        # the non-exact root classes (best-effort / uncapped).
        rate = rate_by_sched[sched] if exact else iface_shape
        grid[int(port)] = {
            "queue": queue_by_class[fc],
            "class": fc,
            "term": int(term),
            "rate_bps": rate,
            "exact": exact,
        }
    return grid


GRID = _fixture_grid()


# --- bash library access ----------------------------------------------------


def run_lib(expr: str) -> subprocess.CompletedProcess:
    cmd = f"source {shlex.quote(str(LIB))}; {expr}"
    return subprocess.run(
        ["bash", "-c", cmd], capture_output=True, text=True, timeout=30
    )


def lib_query(fn: str, port: int) -> subprocess.CompletedProcess:
    return run_lib(f"{fn} {shlex.quote(str(port))}")


class BashScheduleParityTests(unittest.TestCase):
    def test_every_term_port_matches_the_fixture_on_all_four_maps(self):
        self.assertEqual(len(GRID), 24, "fixture must classify 24 ports")
        for port, info in sorted(GRID.items()):
            for fn, key in (
                ("cos_port_to_queue", "queue"),
                ("cos_port_to_class", "class"),
                ("cos_port_to_term", "term"),
                ("cos_port_to_rate_bps", "rate_bps"),
            ):
                with self.subTest(port=port, fn=fn):
                    res = lib_query(fn, port)
                    self.assertEqual(res.returncode, 0, res.stderr)
                    self.assertEqual(res.stdout.strip(), str(info[key]))

    def test_unknown_port_fails_closed_on_every_map(self):
        # An unmapped port is a misconfiguration, never a default (#4241
        # V-11 doctrine). It must exit nonzero and print NOTHING — a
        # partial line would be consumed as a value by callers.
        for port in (5199, 5212, 6212, 5300, 0):
            for fn in (
                "cos_port_to_queue",
                "cos_port_to_class",
                "cos_port_to_term",
                "cos_port_to_rate_bps",
            ):
                with self.subTest(port=port, fn=fn):
                    res = lib_query(fn, port)
                    self.assertNotEqual(res.returncode, 0)
                    self.assertEqual(res.stdout, "")

    def test_exactness_matches_the_fixture(self):
        for port, info in sorted(GRID.items()):
            with self.subTest(port=port):
                res = run_lib(f"cos_port_is_exact {port}; echo rc=$?")
                self.assertEqual(
                    res.stdout.strip(),
                    "rc=0" if info["exact"] else "rc=1",
                )
        # rc 2 is the "not a canonical port at all" answer — distinct from
        # "known non-exact" so callers cannot mistake one for the other.
        res = run_lib("cos_port_is_exact 5212; echo rc=$?")
        self.assertEqual(res.stdout.strip(), "rc=2")

    def test_schedule_ports_array_is_the_fixture_declaration_order(self):
        res = run_lib('printf "%s\\n" "${COS_SCHEDULE_PORTS[@]}"')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(
            [int(p) for p in res.stdout.split()],
            [5200 + t for t in range(12)],
            "COS_SCHEDULE_PORTS must list the grid in queue order",
        )


class PythonScheduleParityTests(unittest.TestCase):
    def test_cos_fixture_spec_agrees_with_the_fixture(self):
        import sys

        sys.path.insert(0, str(ROOT))
        try:
            import cos_fixture_spec
        finally:
            sys.path.remove(str(ROOT))
        schedule = cos_fixture_spec.canonical_cos_schedule()
        self.assertEqual(sorted(schedule), sorted(GRID))
        for port, info in GRID.items():
            got = schedule[port]
            with self.subTest(port=port):
                self.assertEqual(got["forwarding_class"], info["class"])
                self.assertEqual(got["queue_id"], info["queue"])
                self.assertEqual(got["term_id"], info["term"])
                self.assertEqual(got["cap_bps"], info["rate_bps"])
                self.assertEqual(got["exact"], info["exact"])

    def test_validator_maps_still_expose_the_documented_surface(self):
        # cos_be_contention_validate.py's contract: 52xx classes for all
        # 12 terms, exact-class caps only, float values. Widening this
        # surface changes validation outcomes, not just style.
        import sys

        sys.path.insert(0, str(ROOT))
        try:
            import cos_fixture_spec
        finally:
            sys.path.remove(str(ROOT))
        fc = cos_fixture_spec.FORWARDING_CLASS_BY_PORT
        caps = cos_fixture_spec.PORT_CAP_BPS_BY_PORT
        self.assertEqual(sorted(fc), [5200 + t for t in range(12)])
        self.assertEqual(sorted(caps), [5201 + t for t in range(10)])
        for port, info in GRID.items():
            if 5200 <= port <= 5211:
                self.assertEqual(fc[port], info["class"])
            if info["exact"] and 5200 <= port <= 5211:
                self.assertIsInstance(caps[port], float)
                self.assertEqual(caps[port], float(info["rate_bps"]))


class ConsumerWiringTests(unittest.TestCase):
    """The #8244 lesson: pin the SOURCE lines, not just the values.

    A consumer that uses a shared constant without sourcing (bash) or
    importing (Python) the module that defines it gets an EMPTY
    expansion, which passes no value assertion but breaks every run.
    """

    def _text(self, name: str) -> str:
        return (ROOT / name).read_text()

    def test_shell_consumers_source_the_schedule_library(self):
        consumers = {
            "fairness-harness.sh": "cos_port_to_rate_bps",
            "fairness-cos-class-sweep.sh": "COS_SCHEDULE_PORTS",
            "cos-simul-load-smoke.sh": "COS_SCHEDULE_PORTS",
            "cos-gate1-small-four-alone.sh": "COS_SCHEDULE_PORTS",
            "step1-capture.sh": "cos_port_to_term",
            "step1-classify.sh": "cos_port_to_rate_bps",
            "test-mouse-latency.sh": "detect_active_primary",
            "cos-be-contention-harness.sh": "incus_exec_shell",
            "apply-cos-config.sh": "incus_run",
            "step2-sched-switch-capture.sh": "incus_exec",
        }
        for name, marker in consumers.items():
            with self.subTest(consumer=name):
                text = self._text(name)
                self.assertIn("cos-apply-lib.sh", text)
                self.assertIn(marker, text)

    def test_perf_compare_sources_the_shared_wrapper(self):
        text = (
            pathlib.Path(ROOT.parent.parent / "scripts" / "userspace-perf-compare.sh")
        ).read_text()
        self.assertIn("cos-apply-lib.sh", text)
        self.assertIn("incus_exec_shell", text)
        # Its always-through-sg operator contract is preserved via the
        # force knob, not by restating the sg incus invocation.
        self.assertNotIn('sg incus-admin -c "incus', text)

    def test_python_consumers_import_the_spec_module(self):
        validator = self._text("cos_be_contention_validate.py")
        self.assertIn("import cos_fixture_spec", validator)
        # The literal tables are gone from the validator: no restated grid.
        self.assertNotIn("5201: \"iperf-100m\"", validator)
        self.assertNotIn("5201: 100_000_000.0", validator)
        simul = self._text("cos-simul-load-smoke.sh")
        self.assertIn("from cos_fixture_spec import canonical_cos_schedule", simul)
        gate1 = self._text("cos-gate1-small-four-alone.sh")
        self.assertIn("from cos_fixture_spec import canonical_cos_schedule", gate1)

    def test_orchestrator_delegates_to_the_spec_module(self):
        orch = self._text("mouse_latency_orchestrate.py")
        self.assertIn("from cos_fixture_spec import", orch)
        self.assertNotIn("def parse_cos_class_caps", orch)


if __name__ == "__main__":
    unittest.main()
