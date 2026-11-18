"""Policy decisions, including every row of the design's acceptance matrix (section 14.2)."""
import os
from datetime import datetime

import pytest
import yaml

from conftest import CONFIG_DIR
from inventory import Inventory
from models import Tier
from policy_engine import PolicyEngine

N = Tier.NORMAL


@pytest.fixture(scope="module")
def pe():
    inv = Inventory(os.path.join(CONFIG_DIR, "topology.yaml"))
    with open(os.path.join(CONFIG_DIR, "trust.yaml")) as f:
        leases = yaml.safe_load(f)["leases"]
    return PolicyEngine(os.path.join(CONFIG_DIR, "policy.yaml"), inv, leases)


def H(pe, name):
    return pe.inv.by_name(name)


@pytest.mark.parametrize("src,dst,proto,port,allowed,reason", [
    ("u1", "web1", "tcp", 80, True, "R1"),            # T1 users browse web
    ("u1", "web1", "icmp", None, True, "R1"),         # T2 ping allowed by R1 icmp flag
    ("u1", "u2", "icmp", None, False, "NO_MATCHING_RULE"),   # T3 no laptop-to-laptop
    ("u1", "db1", "tcp", 3306, False, "NO_MATCHING_RULE"),   # T4 users never reach the DB
    ("web1", "db1", "tcp", 3306, True, "R3"),         # T5 web tier -> DB tier
    ("cam1", "col1", "tcp", 1883, True, "R4"),        # T6 IoT -> collector
    ("cam1", "cam2", "tcp", 22, False, "NO_MATCHING_RULE"),  # T7 no IoT-to-IoT
    ("adm1", "web1", "tcp", 22, True, "R5"),          # T8 admin ssh (in window)
    ("u2", "rem1", "tcp", 8080, True, "R7"),          # T9 remediation
    ("u1", "dns1", "udp", 53, True, "R2"),
    ("u1", "web1", "tcp", 22, False, "NO_MATCHING_RULE"),    # only port 80 for users
    ("cam1", "web1", "tcp", 80, False, "NO_MATCHING_RULE"),
    ("u2", "web1", "tcp", 8000, True, "R8"),
])
def test_matrix(pe, src, dst, proto, port, allowed, reason):
    d = pe.decide(H(pe, src), H(pe, dst), proto, port, N)
    assert d.allowed is allowed
    assert d.reason == reason


def test_unenrolled(pe):
    assert pe.decide(None, H(pe, "web1"), "tcp", 80, N).reason == "UNENROLLED"


def test_tier_profiles(pe):
    u1, web1, dns1, rem1 = (H(pe, n) for n in ("u1", "web1", "dns1", "rem1"))
    # RESTRICTED: essential only
    assert pe.decide(u1, web1, "tcp", 80, Tier.RESTRICTED).reason == "NOT_ESSENTIAL"
    assert pe.decide(u1, dns1, "udp", 53, Tier.RESTRICTED).allowed
    # QUARANTINED: only remediation
    assert pe.decide(u1, dns1, "udp", 53, Tier.QUARANTINED).reason == "TIER_TOO_LOW"
    assert pe.decide(u1, rem1, "tcp", 8080, Tier.QUARANTINED).allowed
    # admin rules need NORMAL
    assert pe.decide(H(pe, "adm1"), web1, "tcp", 22, Tier.RESTRICTED).reason == "TIER_TOO_LOW"


def test_leases_follow_tier(pe):
    u1, web1 = H(pe, "u1"), H(pe, "web1")
    t = pe.decide(u1, web1, "tcp", 80, Tier.TRUSTED)
    n = pe.decide(u1, web1, "tcp", 80, Tier.NORMAL)
    assert (t.idle_timeout, t.hard_timeout) == (120, 600)
    assert (n.idle_timeout, n.hard_timeout) == (60, 300)


def test_schedule(pe):
    sched_rule = next(r for r in pe.rules if r.id == "R5")
    saved = sched_rule.schedule
    sched_rule.schedule = {"days": ["mon"], "start": "09:00", "end": "18:00"}
    try:
        monday_night = datetime(2026, 10, 19, 23, 0)
        monday_noon = datetime(2026, 10, 19, 12, 0)
        adm1, web1 = H(pe, "adm1"), H(pe, "web1")
        assert pe.decide(adm1, web1, "tcp", 22, N, monday_night).reason == "OUT_OF_SCHEDULE"
        assert pe.decide(adm1, web1, "tcp", 22, N, monday_noon).allowed
    finally:
        sched_rule.schedule = saved


def test_any_allowed_is_bidirectional(pe):
    assert pe.any_allowed(H(pe, "u1"), H(pe, "web1"))
    assert pe.any_allowed(H(pe, "web1"), H(pe, "u1"))      # web1 must resolve u1 to reply
    assert not pe.any_allowed(H(pe, "u1"), H(pe, "db1"))   # invisible
    assert not pe.any_allowed(H(pe, "u1"), H(pe, "u2"))


def test_reply_recognition(pe):
    u1, web1, col1, cam2 = (H(pe, n) for n in ("u1", "web1", "col1", "cam2"))
    assert pe.reply_rule(web1, u1, "tcp", 80) is not None        # web1:80 answering u1
    assert pe.reply_rule(col1, cam2, "tcp", 1883) is not None    # collector answering a camera
    assert pe.reply_rule(web1, u1, "tcp", 22) is None            # not a reply to anything allowed
    assert pe.reply_rule(u1, web1, "tcp", 43210) is None         # a client port is not a service


def test_roles(pe):
    cam1, col1, web1 = H(pe, "cam1"), H(pe, "col1"), H(pe, "web1")
    ok = pe.decide(cam1, col1, "tcp", 1883, N)
    bad = pe.decide(cam1, web1, "tcp", 80, N)
    assert pe.initiates_ok(cam1, ok)
    assert not pe.initiates_ok(cam1, bad)
    assert pe.initiates_ok(H(pe, "u1"), bad)   # users have no role constraint
