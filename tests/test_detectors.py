"""Detector signals, especially that bulk transfers are not mistaken for floods."""
import os

import pytest
import yaml

from conftest import CONFIG_DIR
from detectors import Detectors


@pytest.fixture
def det():
    with open(os.path.join(CONFIG_DIR, "trust.yaml")) as f:
        cfg = yaml.safe_load(f)
    return Detectors(cfg["signals"], cfg["window_s"])


def sigs(events):
    return {e.signal for e in events}


def test_quiet_host(det):
    assert det.evaluate(0, {"u1": {"pps": 5, "tx_Bps": 2000, "rx_Bps": 5000}}) == []


def test_scan(det):
    s = sigs(det.evaluate(0, {"cam1": {"dst_ports": 87, "dst_hosts": 6, "denied": 40}}))
    assert {"E1_DENIED_ATTEMPT", "E2_SCAN_FANOUT"} <= s


def test_syn_flood_detected(det):
    # 5000 pps of 60-byte SYNs, SYN-ACKs come back at a similar size
    f = {"pps": 5000, "tx_Bps": 300000, "rx_Bps": 290000}
    assert "E3_RATE_ANOMALY" in sigs(det.evaluate(0, {"cam2": f}))


def test_udp_flood_detected(det):
    f = {"pps": 8000, "tx_Bps": 8000 * 100, "rx_Bps": 0}
    assert "E3_RATE_ANOMALY" in sigs(det.evaluate(0, {"cam2": f}))


def test_bulk_upload_not_flood(det):
    # uploader: large packets
    f = {"pps": 8000, "tx_Bps": 8000 * 1448, "rx_Bps": 4000 * 66}
    assert det.evaluate(0, {"u2": f}) == []


def test_bulk_download_not_flood(det):
    # downloader: sends many small ACKs but receives far more bytes
    f = {"pps": 4000, "tx_Bps": 4000 * 66, "rx_Bps": 8000 * 1448}
    assert det.evaluate(0, {"u2": f}) == []


def test_packet_in_flood(det):
    assert "E6_PACKETIN_FLOOD" in sigs(det.evaluate(0, {"cam1": {"packet_ins": 500}}))
