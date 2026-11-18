import os

import pytest

from conftest import CONFIG_DIR
from flow_manager import C_ALLOW, cookie, cookie_fields
from inventory import Inventory


@pytest.fixture(scope="module")
def inv():
    return Inventory(os.path.join(CONFIG_DIR, "topology.yaml"))


def test_counts(inv):
    assert len(inv.hosts) == 13
    assert len(inv.switches) == 5


def test_lookups(inv):
    assert inv.by_ip("10.0.2.10").name == "web1"
    assert inv.by_mac("00:00:00:00:03:21").name == "cam1"
    assert inv.at(0x11, 1).name == "u1"
    assert inv.at(0x11, 99) is None


def test_binding(inv):
    assert inv.binding_ok(0x11, 1, "00:00:00:00:01:11", "10.0.1.11")
    assert not inv.binding_ok(0x11, 1, "00:00:00:00:01:11", "10.0.2.20")   # spoofed IP
    assert not inv.binding_ok(0x11, 2, "00:00:00:00:01:11", "10.0.1.11")   # wrong port


def test_forwarding_ports(inv):
    web1 = inv.by_name("web1")
    assert inv.out_port(0x12, web1) == 1      # local on s2
    assert inv.out_port(0x11, web1) == 10     # s1 uplink to core
    assert inv.out_port(0x10, web1) == 2      # core -> s2
    rem1 = inv.by_name("rem1")
    assert inv.out_port(0x10, rem1) == 5      # attached to core
    assert inv.uplink_ports(0x10) == {1, 2, 3, 4}


def test_cookie_roundtrip():
    c = cookie(7, C_ALLOW, 42)
    assert cookie_fields(c) == (7, C_ALLOW, 42)
