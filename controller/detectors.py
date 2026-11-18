"""Detectors E1-E7: turn per-host window features into explainable trust events.

Pure Python. Spec: SDS_Phase2_Design.md section 7.2.

Features per host for one window (built by monitor.py):
  pps            packets/s the host sent (edge-port rx counter)
  tx_Bps, rx_Bps bytes/s the host sent / received
  dst_hosts      distinct destination IPs attempted via the controller (incl. hidden ARP)
  dst_ports      distinct (dst_ip, port) pairs attempted via the controller
  denied         denied decisions + hidden-ARP targets + hits on deny rules
  role_viol      flows the host's role should never initiate
  packet_ins     packet-ins the host caused
  out_of_sched   requests refused by a schedule
"""
from typing import Dict, List

from models import TrustEvent


class Detectors:
    def __init__(self, signal_cfg: dict, window_s: float):
        self.cfg = signal_cfg
        self.window_s = window_s
        self.baseline_pps: Dict[str, float] = {}   # EWMA per host (E3)

    def evaluate(self, now: float, features: Dict[str, dict]) -> List[TrustEvent]:
        events: List[TrustEvent] = []
        for host, f in features.items():
            ev = lambda sig, **evidence: events.append(TrustEvent(now, host, sig, evidence))

            # E1: denied attempts (forbidden services, hidden hosts, repeated drops)
            if f.get("denied", 0) > 0:
                ev("E1_DENIED_ATTEMPT", count=f["denied"])

            # E2: scan fan-out (one trigger per exceeded dimension)
            c2 = self.cfg["E2_SCAN_FANOUT"]
            trig = int(f.get("dst_ports", 0) > c2["distinct_ports"]) + int(f.get("dst_hosts", 0) > c2["distinct_hosts"])
            if trig:
                ev("E2_SCAN_FANOUT", count=trig, distinct_ports=f.get("dst_ports", 0),
                   distinct_hosts=f.get("dst_hosts", 0), window_s=self.window_s)

            # E3: rate anomaly. A flood is high packet rate of SMALL packets that is
            # NOT a bulk receive (a downloader sends many small ACKs but receives far
            # more bytes; an uploader sends large packets). This keeps legitimate
            # bulk transfers (scenario S6) from being punished.
            c3 = self.cfg["E3_RATE_ANOMALY"]
            pps = f.get("pps", 0.0)
            tx, rx = f.get("tx_Bps", 0.0), f.get("rx_Bps", 0.0)
            mean = tx / pps if pps else 0.0
            base = self.baseline_pps.get(host)
            thr = max(c3["min_pps"], c3["baseline_factor"] * base if base else 0.0)
            flood = pps > thr and mean < c3["max_mean_pkt_bytes"] and rx < c3["rx_tx_ratio"] * tx
            if flood:
                ev("E3_RATE_ANOMALY", count=1, pps=round(pps), threshold=round(thr),
                   mean_pkt_bytes=round(mean), rx_tx_ratio=round(rx / tx, 2) if tx else 0)
            else:
                a = c3["ewma_alpha"]
                self.baseline_pps[host] = pps if base is None else a * pps + (1 - a) * base

            # E4: role violation
            if f.get("role_viol", 0) > 0:
                ev("E4_ROLE_VIOLATION", count=f["role_viol"])

            # E6: packet-in flood (controller saturation attempt)
            c6 = self.cfg["E6_PACKETIN_FLOOD"]
            limit = c6["rate_per_s"] * self.window_s + c6["burst"]
            if f.get("packet_ins", 0) > limit:
                ev("E6_PACKETIN_FLOOD", count=1, packet_ins=f["packet_ins"], limit=limit)

            # E7: out-of-schedule access attempts
            if f.get("out_of_sched", 0) > 0:
                ev("E7_OUT_OF_SCHEDULE", count=f["out_of_sched"])
        return events
