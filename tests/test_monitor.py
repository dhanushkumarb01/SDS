"""Traffic attribution: rates go to the flow INITIATOR, never to a flood victim."""
import os
from types import SimpleNamespace as NS

import pytest
import yaml

from conftest import CONFIG_DIR
from detectors import Detectors
from flow_manager import C_ALLOW, C_DENY, C_REV, cookie
from inventory import Inventory
from monitor import Monitor


@pytest.fixture
def env():
    inv = Inventory(os.path.join(CONFIG_DIR, "topology.yaml"))
    with open(os.path.join(CONFIG_DIR, "trust.yaml")) as f:
        cfg = yaml.safe_load(f)
    return inv, Monitor(inv), Detectors(cfg["signals"], cfg["window_s"])


def stat(c, pk, by):
    return NS(cookie=c, packet_count=pk, byte_count=by)


def test_syn_flood_blames_attacker_not_victim(env):
    inv, mon, det = env
    cam2 = inv.by_name("cam2")
    fwd, rev = cookie(cam2.host_id, C_ALLOW, 1), cookie(cam2.host_id, C_REV, 2)
    mon.features(0.0)                                     # start the window clock
    mon.on_flow_stats(0x13, [stat(fwd, 0, 0)], 0)         # cam2's edge switch
    mon.on_flow_stats(0x12, [stat(rev, 0, 0)], 0)         # col1's edge switch (SYN-ACKs)
    mon.counters.clear()
    mon.features(5.0)
    # 5 s of 5000 pps SYNs answered by 5000 pps SYN-ACKs
    mon.on_flow_stats(0x13, [stat(fwd, 25000, 25000 * 60)], 9)
    mon.on_flow_stats(0x12, [stat(rev, 25000, 25000 * 58)], 9)
    feats = mon.features(10.0)
    assert feats["cam2"]["pps"] == pytest.approx(5000)
    assert feats["col1"]["pps"] == 0                       # the victim initiated nothing
    flagged = {e.host for e in det.evaluate(10.0, feats) if e.signal == "E3_RATE_ANOMALY"}
    assert flagged == {"cam2"}


def test_deny_rule_hits_count_as_denied(env):
    inv, mon, _ = env
    u1 = inv.by_name("u1")
    d = cookie(u1.host_id, C_DENY, 3)
    mon.features(0.0)
    mon.on_flow_stats(0x11, [stat(d, 0, 0)], 0)
    mon.on_flow_stats(0x11, [stat(d, 4, 240)], 4)          # 4 SYN retries hit the drop rule
    assert mon.features(5.0)["u1"]["denied"] == 4
