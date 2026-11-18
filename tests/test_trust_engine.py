"""Trust maths: caps, fast drop / slow recovery, hysteresis, probation, overrides."""
import os

import pytest
import yaml

from conftest import CONFIG_DIR
from models import Tier, TrustEvent
from trust_engine import TrustEngine


@pytest.fixture
def te():
    with open(os.path.join(CONFIG_DIR, "trust.yaml")) as f:
        cfg = yaml.safe_load(f)
    return TrustEngine(cfg, ["cam1", "u1"], ledger_path=None)


def E(host, sig, t, **ev):
    return TrustEvent(t, host, sig, ev)


def test_initial_state(te):
    assert te.score("cam1") == 75
    assert te.tier("cam1") == Tier.NORMAL


def test_caps_per_window(te):
    # 50 denied attempts cost at most the E1 cap (10), not 100
    te.end_window(100, [E("cam1", "E1_DENIED_ATTEMPT", 100, count=50)])
    assert te.score("cam1") == 65


def test_scan_drives_to_quarantine_in_two_windows(te):
    w = lambda t: [E("cam1", "E1_DENIED_ATTEMPT", t, count=20),
                   E("cam1", "E2_SCAN_FANOUT", t, count=1)]
    ch1 = te.end_window(100, w(100))                  # 75 - 10 - 15 = 50
    assert te.score("cam1") == 50 and ch1[0].new == Tier.RESTRICTED
    te.end_window(105, w(105))                        # 50 - 25 = 25
    assert te.tier("cam1") == Tier.QUARANTINED


def test_scan_with_role_violation_quarantines_at_once(te):
    te.end_window(100, [E("cam1", "E1_DENIED_ATTEMPT", 100, count=20),
                        E("cam1", "E2_SCAN_FANOUT", 100, count=1),
                        E("cam1", "E4_ROLE_VIOLATION", 100, count=3)])   # 75-10-15-20 = 30
    assert te.tier("cam1") == Tier.QUARANTINED


def test_spoofing_is_immediate(te):
    ch = te.add_event(E("u1", "E5_SPOOFING", 50, count=1))
    assert te.score("u1") == 35
    assert ch is not None and ch.new == Tier.QUARANTINED


def test_slow_recovery_with_quiet_period(te):
    te.end_window(100, [E("cam1", "E2_SCAN_FANOUT", 100, count=1)])   # 75 -> 60
    te.end_window(120, [])                                            # quiet 20 s < 30 s: no recovery
    assert te.score("cam1") == 60
    te.end_window(130, [])                                            # quiet 30 s: +1
    assert te.score("cam1") == 61


def test_hysteresis_upgrade(te):
    te.end_window(100, [E("cam1", "E2_SCAN_FANOUT", 100, count=1)])   # 60 RESTRICTED
    assert te.tier("cam1") == Tier.RESTRICTED
    te.state["cam1"].score = 72                       # above 70 but below 70 + margin 5
    # recovery +1 per window: 73 (t130), 74, 75 (t140), 76, 77 (t150)
    for t in (130, 135, 140, 145):
        te.end_window(t, [])
        assert te.tier("cam1") == Tier.RESTRICTED      # only 2 windows >= 75 so far
    te.end_window(150, [])                            # 3rd consecutive window >= 75
    assert te.tier("cam1") == Tier.NORMAL


def test_probation_ceiling(te):
    te.add_event(E("u1", "E5_SPOOFING", 50, count=1))                 # quarantined
    te.state["u1"].score = 46
    for t in range(100, 120, 5):
        te.end_window(t, [])                                          # -> RESTRICTED, probation starts
    assert te.tier("u1") == Tier.RESTRICTED
    te.state["u1"].score = 99
    te.end_window(125, [])
    assert te.score("u1") == 99                                       # set manually; ceiling applies to recovery
    te.state["u1"].score = 84
    te.end_window(130, [])
    assert te.score("u1") == 84                                       # cannot recover past 84 on probation


def test_override(te):
    ch = te.override("u1", Tier.QUARANTINED, 10)
    assert ch.new == Tier.QUARANTINED and te.tier("u1") == Tier.QUARANTINED
    ch = te.override("u1", None, 20)
    assert te.tier("u1") == Tier.NORMAL


def test_ledger_explains(te):
    te.end_window(100, [E("cam1", "E2_SCAN_FANOUT", 100, count=1, distinct_ports=87)])
    entries = te.events_since(0)
    scan = [e for e in entries if e["signal"] == "E2_SCAN_FANOUT"][0]
    assert scan["delta"] == -15 and scan["evidence"]["distinct_ports"] == 87
    assert any(e["signal"] == "TIER_CHANGE" for e in entries)
