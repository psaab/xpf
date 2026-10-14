"""The canonical 12-port CoS schedule for Python consumers (#13070 / D10-15).

The port -> (queue, forwarding-class, filter-term, rate-cap) grid defined by
``test/incus/cos-iperf-config.set`` used to be restated as literals in
``cos_be_contention_validate.py`` and inside the Python heredocs of
``cos-simul-load-smoke.sh`` / ``cos-gate1-small-four-alone.sh`` — independent
copies that drifted from the fixture whenever one was edited without the
others. This module is the single Python source of truth: everything is
DERIVED by parsing the fixture, so the copies cannot drift by construction.

The shell half of the same single-sourcing lives in ``cos-apply-lib.sh``
(``cos_port_to_queue`` and friends), and ``test_cos_apply_lib.py`` binds BOTH
sides to ``cos-iperf-config.set`` term by term — a fixture edit without the
matching lib edit reds ``make test-incus-lib``.

``parse_cos_class_caps`` (and its error type) moved here from
``mouse_latency_orchestrate.py``, which now imports them back; it is the
fixture parser the #1365 env-consistency guard has always relied on.
"""

from __future__ import annotations

import os
import re

# Default location of the canonical CoS fixture relative to this file.
DEFAULT_COS_SET = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "cos-iperf-config.set"
)

# Junos transmit-rate / shaping-rate unit suffixes. Decimal SI
# (1k = 1000), matching how iperf3 reports bits/sec and how the rest
# of the harness family converts the fixture rates.
_RATE_SUFFIX_MULTIPLIER = {
    "": 1,
    "k": 1_000,
    "m": 1_000_000,
    "g": 1_000_000_000,
    "t": 1_000_000_000_000,
}


class CoSFixtureError(ValueError):
    """Raised when the CoS fixture cannot resolve a port's class cap."""


def parse_junos_rate(token: str) -> int | None:
    """Convert a Junos rate token (e.g. '1.0g', '100m', '25g') to bps.

    Returns None for tokens that are not a numeric-rate form (so the
    caller can skip non-rate scheduler attributes like 'exact').
    """
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([kmgt]?)", token.strip().lower())
    if not m:
        return None
    value = float(m.group(1))
    mult = _RATE_SUFFIX_MULTIPLIER[m.group(2)]
    return int(value * mult)


def parse_cos_class_caps(set_text: str) -> dict:
    """Parse a cos-iperf-config.set fixture into a per-port rate table.

    Returns a dict keyed by destination-port (int) with values:
        {"forwarding_class": str,
         "scheduler": str,
         "cap_bps": int,          # exact rate, else interface shaping-rate
         "exact": bool}           # True if scheduler is transmit-rate exact
    plus, when the fixture carries them,
         "queue_id": int | None,  # forwarding-classes queue id (None when
                                  # the fixture declares no queue for the
                                  # class — synthetic minimal fixtures)
         "term_id": int | str     # firewall filter term that classifies the
                                  # port (int when the term id is numeric)

    The ceiling is the scheduler's `transmit-rate` for `exact` classes
    (the class is hard-capped at that aggregate per
    docs/cos-traffic-shaping.md), and the interface `shaping-rate` for
    non-exact classes (best-effort / uncapped), which can only ever burst
    to the interface shaper. This is the single source of truth the
    env-consistency guard compares SHAPER_BPS against — it is derived
    directly from the applied fixture so it cannot drift from it.
    """
    # port -> forwarding-class, forwarding-class -> scheduler,
    # scheduler -> (rate_bps, exact), plus the interface shaping-rate.
    port_to_class: dict = {}
    class_to_sched: dict = {}
    sched_rate: dict = {}
    sched_exact: dict = {}
    iface_shaping_bps: int | None = None

    term_class: dict = {}  # term-id -> forwarding-class
    term_ports: dict = {}  # term-id -> list[int]
    fc_to_queue: dict = {}  # forwarding-class -> queue id

    for raw in set_text.splitlines():
        line = raw.strip()
        if not line.startswith("set "):
            continue
        toks = line.split()

        # set ... filter <name> term <id> from destination-port <port>
        if "destination-port" in toks and "term" in toks:
            try:
                term = toks[toks.index("term") + 1]
                port = int(toks[toks.index("destination-port") + 1])
            except (ValueError, IndexError):
                continue
            term_ports.setdefault(term, []).append(port)
            continue

        # set ... filter <name> term <id> then forwarding-class <fc>
        if "forwarding-class" in toks and "term" in toks and "then" in toks:
            try:
                term = toks[toks.index("term") + 1]
                fc = toks[toks.index("forwarding-class") + 1]
            except IndexError:
                continue
            term_class[term] = fc
            continue

        # set class-of-service forwarding-classes queue <n> <fc>
        if "forwarding-classes" in toks and "queue" in toks:
            try:
                queue = int(toks[toks.index("queue") + 1])
                fc = toks[toks.index("queue") + 2]
            except (ValueError, IndexError):
                continue
            fc_to_queue[fc] = queue
            continue

        # set class-of-service scheduler-maps <map> forwarding-class <fc>
        #     scheduler <sched>
        if (
            "scheduler-maps" in toks
            and "forwarding-class" in toks
            and "scheduler" in toks
        ):
            try:
                fc = toks[toks.index("forwarding-class") + 1]
                sched = toks[toks.index("scheduler") + 1]
            except IndexError:
                continue
            class_to_sched[fc] = sched
            continue

        # set class-of-service schedulers <sched> transmit-rate <val|exact>
        if "schedulers" in toks and "transmit-rate" in toks:
            try:
                sched = toks[toks.index("schedulers") + 1]
                val = toks[toks.index("transmit-rate") + 1]
            except IndexError:
                continue
            if val == "exact":
                sched_exact[sched] = True
            else:
                rate = parse_junos_rate(val)
                if rate is not None:
                    sched_rate[sched] = rate
            continue

        # set class-of-service interfaces <if> unit <u> shaping-rate <val>
        if "interfaces" in toks and "shaping-rate" in toks:
            try:
                val = toks[toks.index("shaping-rate") + 1]
            except IndexError:
                continue
            rate = parse_junos_rate(val)
            if rate is not None:
                iface_shaping_bps = rate
            continue

    # Stitch term ports -> forwarding-class (and remember the term id).
    port_term: dict = {}
    for term, ports in term_ports.items():
        fc = term_class.get(term)
        if fc is None:
            continue
        for port in ports:
            port_to_class[port] = fc
            port_term[port] = int(term) if term.isdigit() else term

    out: dict = {}
    for port, fc in port_to_class.items():
        sched = class_to_sched.get(fc)
        if sched is None:
            # A classified port whose forwarding-class has no scheduler-map
            # entry would silently fall through to the interface-shaper cap
            # below, masking fixture drift/misparse and yielding a wrong
            # cap. The guard's whole point is that it cannot drift from the
            # fixture, so refuse rather than guess.
            raise CoSFixtureError(
                f"port {port} class {fc} has no scheduler-map entry "
                f"(forwarding-class is classified but unscheduled); the "
                f"CoS fixture cannot resolve its rate cap"
            )
        exact = bool(sched_exact.get(sched, False))
        if exact:
            cap = sched_rate.get(sched)
            if cap is None:
                raise CoSFixtureError(
                    f"port {port} class {fc} scheduler {sched} is "
                    f"transmit-rate exact but has no numeric transmit-rate"
                )
        else:
            # Non-exact classes (best-effort / uncapped) are bounded only
            # by the interface shaping-rate.
            if iface_shaping_bps is None:
                raise CoSFixtureError(
                    f"port {port} class {fc} is non-exact but the fixture "
                    f"defines no interface shaping-rate"
                )
            cap = iface_shaping_bps
        out[port] = {
            "forwarding_class": fc,
            "scheduler": sched,
            "cap_bps": cap,
            "exact": exact,
            "queue_id": fc_to_queue.get(fc),
            "term_id": port_term[port],
        }
    return out


# The canonical grid: terms 0..11 on BOTH port families (5200+t / 6200+t).
_CANONICAL_TERMS = 12


def canonical_cos_schedule(set_text: str | None = None) -> dict:
    """Return the validated canonical 12-term CoS schedule.

    Parses the fixture (default: cos-iperf-config.set beside this module)
    and REFUSES anything that is not the full canonical grid: every term
    0..11 must classify both of its ports (5200+term and 6200+term) into
    one forwarding class with a declared queue id. A truncated or
    hand-mangled fixture raises CoSFixtureError instead of silently
    answering lookups for the half that survived (fail-closed doctrine).

    Returns a dict keyed by port (int) with the parse_cos_class_caps value
    shape: forwarding_class, scheduler, cap_bps, exact, queue_id, term_id.
    """
    if set_text is None:
        with open(DEFAULT_COS_SET) as f:
            set_text = f.read()
    caps = parse_cos_class_caps(set_text)

    sched: dict = {}
    for term in range(_CANONICAL_TERMS):
        ports = (5200 + term, 6200 + term)
        infos = []
        for port in ports:
            info = caps.get(port)
            if info is None:
                raise CoSFixtureError(
                    f"canonical fixture is missing term {term} port {port}"
                )
            if info["queue_id"] is None:
                raise CoSFixtureError(
                    f"port {port} class {info['forwarding_class']} has no "
                    f"forwarding-classes queue declaration"
                )
            if info["term_id"] != term:
                raise CoSFixtureError(
                    f"port {port} is classified by term {info['term_id']!r}, "
                    f"expected term {term}"
                )
            infos.append(info)
        if infos[0]["forwarding_class"] != infos[1]["forwarding_class"]:
            raise CoSFixtureError(
                f"term {term} maps {ports[0]} and {ports[1]} to different "
                f"forwarding classes"
            )
        sched[ports[0]] = infos[0]
        sched[ports[1]] = infos[1]
    return sched


# ---------------------------------------------------------------------------
# Legacy-compatible views, derived (not restated).
#
# cos_be_contention_validate.py re-binds these under its own names. They are
# deliberately scoped to the 520x (forward / elephant) family and, for the
# caps, to the exact classes only — that is exactly the surface the
# validator's manifest contract exercised before #13070, including which
# lookups miss (62xx and the two non-exact root classes are absent on
# purpose; widening them would change validation outcomes, not just style).
# ---------------------------------------------------------------------------

_SCHEDULE = canonical_cos_schedule()

FORWARDING_CLASS_BY_PORT = {
    port: info["forwarding_class"]
    for port, info in _SCHEDULE.items()
    if 5200 <= port <= 5211
}

PORT_CAP_BPS_BY_PORT = {
    port: float(info["cap_bps"])
    for port, info in _SCHEDULE.items()
    if info["exact"] and 5200 <= port <= 5211
}
