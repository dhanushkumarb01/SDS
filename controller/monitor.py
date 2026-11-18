"""Monitor: packet-in observations + flow statistics -> per-host window features.

Pure Python (the Ryu app forwards stats replies to it). Spec: design 7 and 9.4.

Traffic rates are attributed to the host that INITIATED each flow, using the
cookies of the authorization rules:
  C_ALLOW (forward rule)  packets/bytes the initiator sent      -> pps, tx_Bps
  C_DENY  (drop rule)     packets the host tried to send        -> pps, tx_Bps, denied
  C_REV   (reply rule)    bytes the responder sent back to it   -> rx_Bps
So a flood victim answering with SYN-ACKs is never mistaken for the attacker.
"""
from collections import defaultdict
from typing import Dict, Optional

from flow_manager import C_ALLOW, C_DENY, C_REV, cookie_fields


def _new_counters():
    return {"dst_hosts": set(), "dst_ports": set(), "hidden": set(), "denied": 0,
            "role_viol": 0, "packet_ins": 0, "out_of_sched": 0,
            "tx_pk": 0, "tx_by": 0, "rx_by": 0, "deny_hits": 0}


class Monitor:
    def __init__(self, inventory):
        self.inv = inventory
        self.counters = defaultdict(_new_counters)
        self._prev: Dict[tuple, tuple] = {}          # (dpid, cookie) -> (packets, bytes)
        self._last_features: Optional[float] = None
        self.flow_counts: Dict[int, int] = {}        # dpid -> number of flow entries
        self.allow_counts: Dict[int, int] = {}       # dpid -> number of allowed-flow rules

    # ---- packet-in path ------------------------------------------------
    def note_packet_in(self, host: str):
        self.counters[host]["packet_ins"] += 1

    def note_request(self, host: str, dst_ip: str, port, denied: bool, role_viol: bool, out_of_sched: bool):
        c = self.counters[host]
        c["dst_hosts"].add(dst_ip)
        c["dst_ports"].add((dst_ip, port))
        c["denied"] += int(denied)
        c["role_viol"] += int(role_viol)
        c["out_of_sched"] += int(out_of_sched)

    def note_hidden_arp(self, host: str, dst_ip: str):
        c = self.counters[host]
        c["dst_hosts"].add(dst_ip)
        c["hidden"].add(dst_ip)

    # ---- statistics replies --------------------------------------------
    def on_flow_stats(self, dpid: int, body, now: float):
        self.flow_counts[dpid] = len(body)
        allows = 0
        seen = set()
        for st in body:
            host_id, ctype, _ = cookie_fields(st.cookie)
            if ctype not in (C_ALLOW, C_REV, C_DENY) or host_id == 0:
                continue
            if ctype in (C_ALLOW, C_REV):
                allows += 1
            key = (dpid, st.cookie)
            seen.add(key)
            pk0, by0 = self._prev.get(key, (0, 0))
            dpk, dby = max(0, st.packet_count - pk0), max(0, st.byte_count - by0)
            self._prev[key] = (st.packet_count, st.byte_count)
            h = self.inv.by_id(host_id)
            if h is None or (dpk == 0 and dby == 0):
                continue
            c = self.counters[h.name]
            if ctype == C_REV:
                c["rx_by"] += dby
            else:
                c["tx_pk"] += dpk
                c["tx_by"] += dby
                if ctype == C_DENY:
                    c["deny_hits"] += dpk
        # forget rules that no longer exist on this switch
        for key in [k for k in self._prev if k[0] == dpid and k not in seen]:
            del self._prev[key]
        self.allow_counts[dpid] = allows

    # ---- window --------------------------------------------------------
    def features(self, now: float) -> Dict[str, dict]:
        """Per-host features for the window that just ended; resets counters."""
        dt = (now - self._last_features) if self._last_features else None
        self._last_features = now
        out = {}
        for name in self.inv.hosts:
            c = self.counters.get(name, _new_counters())
            rate = (lambda v: v / dt) if dt else (lambda v: 0.0)
            out[name] = {"pps": rate(c["tx_pk"]), "tx_Bps": rate(c["tx_by"]), "rx_Bps": rate(c["rx_by"]),
                         "dst_hosts": len(c["dst_hosts"]), "dst_ports": len(c["dst_ports"]),
                         "denied": c["denied"] + len(c["hidden"]) + c["deny_hits"],
                         "role_viol": c["role_viol"], "packet_ins": c["packet_ins"],
                         "out_of_sched": c["out_of_sched"]}
        self.counters.clear()
        return out

    def total_flows(self) -> int:
        return sum(self.flow_counts.values())

    def total_allow(self) -> int:
        return sum(self.allow_counts.values())
