"""AEGIS-ZT Ryu application (entry point).

Run:  ryu-manager --ofp-tcp-listen-port 6653 --wsapi-port 8080 controller/aegis_app.py

Modes (config/trust.yaml "mode", or env AEGIS_MODE):
  open  bring-up: identity admission, no policy
  B0    flat baseline: no admission, no policy (the "castle")
  B1    static zones: admission + default-deny policy, trust frozen at NORMAL
  B2    AEGIS-ZT: admission + policy + live trust engine with graded tiers

Environment overrides: AEGIS_MODE, AEGIS_CONFIG (dir), AEGIS_TOPOLOGY (file),
AEGIS_LOG_DIR (dir).
"""
import os
import sys
import time
from collections import deque
from datetime import datetime

import psutil
import yaml
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, icmp, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
CONFIG_DIR = os.environ.get("AEGIS_CONFIG", os.path.join(ROOT, "config"))
TOPOLOGY_FILE = os.environ.get("AEGIS_TOPOLOGY", os.path.join(CONFIG_DIR, "topology.yaml"))
LOG_DIR = os.environ.get("AEGIS_LOG_DIR", os.path.join(ROOT, "logs"))

from arp_proxy import ArpProxy  # noqa: E402
from detectors import Detectors  # noqa: E402
from flow_manager import (C_ALLOW, C_DENY, C_QUAR, C_REV, T_ADMISSION, T_AUTH,  # noqa: E402
                          FlowManager, cookie, cookie_fields)
from inventory import Inventory  # noqa: E402
from metrics import MetricsLogger  # noqa: E402
from models import Tier, TrustEvent  # noqa: E402
from monitor import Monitor  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
from rest_api import AegisRestController  # noqa: E402
from trust_engine import TrustEngine  # noqa: E402

MODES = ("open", "B0", "B1", "B2")


class AegisZT(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        with open(os.path.join(CONFIG_DIR, "trust.yaml")) as f:
            self.settings = yaml.safe_load(f)
        self.mode = os.environ.get("AEGIS_MODE", self.settings.get("mode", "open"))
        if self.mode not in MODES:
            raise ValueError("unknown mode %r (use one of %s)" % (self.mode, MODES))
        self.window_s = float(self.settings["window_s"])

        self.inventory = Inventory(TOPOLOGY_FILE)
        self.policy = PolicyEngine(os.path.join(CONFIG_DIR, "policy.yaml"), self.inventory,
                                   self.settings["leases"])
        os.makedirs(LOG_DIR, exist_ok=True)
        self.metrics = MetricsLogger(LOG_DIR)
        self.trust = TrustEngine(self.settings, list(self.inventory.hosts),
                                 os.path.join(LOG_DIR, "trust_ledger.jsonl"))
        self.detectors = Detectors(self.settings["signals"], self.window_s)
        self.monitor = Monitor(self.inventory)
        self.flows = FlowManager(self.logger)
        self.arp = ArpProxy(self.inventory, self._is_reachable, self._on_arp_spoof,
                            self._on_hidden, self.logger)
        rem = self.settings["remediation"]
        self.remediation = (self.inventory.by_name(rem["host"]), int(rem["port"]))

        self.datapaths = {}
        self._stats_buf = {}
        self.started = time.time()
        self.decision_us = deque(maxlen=2000)
        self.n_decisions = 0
        self.n_packet_in = 0
        self._pin_window = 0
        self.last_perf = {}
        self.proc = psutil.Process()
        self.proc.cpu_percent(None)

        kwargs["wsgi"].register(AegisRestController, {"aegis_app": self})
        hub.spawn(self._loop)
        self.logger.info("AEGIS-ZT started: mode=%s, %d enrolled hosts, %d switches, logs=%s",
                         self.mode, len(self.inventory.hosts), len(self.inventory.switches), LOG_DIR)

    # ================================================================ helpers
    @property
    def policy_on(self) -> bool:
        return self.mode in ("B1", "B2")

    @property
    def trust_on(self) -> bool:
        return self.mode == "B2"

    def tier_of(self, name: str) -> Tier:
        return self.trust.tier(name) if self.trust_on else Tier.NORMAL

    def dp_of(self, host):
        sw = self.inventory.switches.get(host.switch)
        return self.datapaths.get(sw.dpid) if sw else None

    # ======================================================= switch lifecycle
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_features(self, ev):
        dp = ev.msg.datapath
        sw = self.inventory.switch_by_dpid(dp.id)
        if sw is None:
            self.logger.warning("Unknown switch dpid=%#x connected; ignoring", dp.id)
            return
        self.datapaths[dp.id] = dp
        self.flows.install_pipeline(dp, self.inventory,
                                    admission=self.mode != "B0",
                                    auth_miss_to_controller=self.policy_on)
        # re-apply quarantine profiles if the switch reconnects
        for h in self.inventory.hosts.values():
            if h.switch == sw.name and self.tier_of(h.name) == Tier.QUARANTINED:
                self.flows.install_quarantine(dp, h, self.remediation[0].ip, self.remediation[1])
        self.logger.info("Pipeline installed on %s (dpid=%#x)", sw.name, dp.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def on_state_change(self, ev):
        if ev.datapath and ev.datapath.id in self.datapaths:
            del self.datapaths[ev.datapath.id]

    # ============================================================= packet-in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        self.n_packet_in += 1
        self._pin_window += 1
        local = self.inventory.at(dp.id, in_port)
        if local:
            self.monitor.note_packet_in(local.name)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            if self.mode == "B0":
                self._flood_arp(dp, in_port, msg.data)   # a real flat L2 network broadcasts ARP
            else:
                self.arp.handle(dp, in_port, pkt)
            return
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None:
            return
        if msg.table_id == T_ADMISSION:
            self._on_admission_miss(dp, in_port, eth, ip, local)
        elif msg.table_id == T_AUTH:
            self._authorize(dp, in_port, msg, pkt, ip)

    def _flood_arp(self, dp, in_port, data):
        """B0 baseline only: deliver ARP to every host port (classic broadcast domain),
        so ARP spoofing behaves as it would on an unprotected flat network."""
        for other in self.datapaths.values():
            for h in self.inventory.hosts_on(other.id):
                if other.id == dp.id and h.port == in_port:
                    continue
                self.flows.packet_out(other, other.ofproto.OFPP_CONTROLLER, h.port, data)

    def _l4(self, pkt, ip):
        if ip.proto == 6:
            t = pkt.get_protocol(tcp.tcp)
            return "tcp", t.src_port, t.dst_port, None
        if ip.proto == 17:
            u = pkt.get_protocol(udp.udp)
            return "udp", u.src_port, u.dst_port, None
        if ip.proto == 1:
            i = pkt.get_protocol(icmp.icmp)
            return "icmp", None, None, i.type if i else None
        return None, None, None, None

    def _authorize(self, dp, in_port, msg, pkt, ip):
        """Table-2 miss: the Zero Trust decision for a new flow (design 9.2/9.3)."""
        src, dst = self.inventory.by_ip(ip.src), self.inventory.by_ip(ip.dst)
        if src is None:
            return
        proto, sport, dport, icmp_type = self._l4(pkt, ip)
        if proto is None:
            return
        t0 = time.perf_counter()
        now = time.time()

        decision = self.policy.decide(src, dst, proto, dport, self.tier_of(src.name), datetime.now())

        # Stateless reply recognition: a packet that answers a request the policy
        # covers (e.g. web1:80 -> u1 after the lease expired) is a REPLY, not a new
        # flow by the responder. It is re-authorized as the initiator's flow, or,
        # if the initiator has since lost that access, dropped silently. Either way
        # the responder is never penalised (a flood victim must not be blamed).
        if not decision.allowed and dst is not None:
            is_reply_shape = (proto == "icmp" and icmp_type == 0) or (proto in ("tcp", "udp") and sport is not None)
            if is_reply_shape and self.policy.reply_rule(src, dst, proto, sport):
                rport = sport if proto != "icmp" else None
                back = self.policy.decide(dst, src, proto, rport, self.tier_of(dst.name), datetime.now())
                init_dp = self.dp_of(dst)
                if back.allowed and init_dp is not None:
                    self.flows.install_allow(init_dp, dp, dst, src, proto, rport, back.idle_timeout, back.hard_timeout)
                    self.flows.packet_out(dp, in_port, self.inventory.out_port(dp.id, dst), msg.data)
                else:
                    self.flows.install_deny(dp, src, ip.dst, proto, dport, int(self.settings["deny_rule_idle_s"]),
                                            attribute=False)
                    back = type(back)("DENY", "REPLY_" + back.reason, back.rule_id)
                us = (time.perf_counter() - t0) * 1e6
                self.metrics.log_decision(now, src.name, dst.name, proto, sport, back, us)
                return

        if decision.allowed:
            dst_dp = self.dp_of(dst)
            if dst_dp is None:
                return
            self.flows.install_allow(dp, dst_dp, src, dst, proto, dport,
                                     decision.idle_timeout, decision.hard_timeout)
            self.flows.packet_out(dp, in_port, self.inventory.out_port(dp.id, dst), msg.data)
        else:
            self.flows.install_deny(dp, src, ip.dst, proto, dport, int(self.settings["deny_rule_idle_s"]))

        us = (time.perf_counter() - t0) * 1e6
        self.decision_us.append(us)
        self.n_decisions += 1
        role_viol = src.role in self.policy.roles and not self.policy.initiates_ok(src, decision)
        self.monitor.note_request(src.name, ip.dst, dport, denied=not decision.allowed,
                                  role_viol=role_viol, out_of_sched=decision.reason == "OUT_OF_SCHEDULE")
        self.metrics.log_decision(now, src.name, dst.name if dst else ip.dst, proto, dport, decision, us)

    # ===================================================== spoofing / hidden
    def _on_admission_miss(self, dp, in_port, eth, ip, local):
        if in_port in self.inventory.uplink_ports(dp.id):
            return
        host_id = local.host_id if local else 0
        self.flows.install_spoof_drop(dp, in_port, ip.src, host_id, int(self.settings["spoof_drop_idle_s"]))
        evidence = {"src_mac": eth.src, "claimed_ip": ip.src, "switch": hex(dp.id), "port": in_port,
                    "reason": "IP_BINDING_MISMATCH" if local else "UNENROLLED_DEVICE"}
        self._spoof(local, evidence)

    def _on_arp_spoof(self, host, evidence):
        self._spoof(host, evidence)

    def _spoof(self, host, evidence):
        now = time.time()
        name = host.name if host else "UNENROLLED"
        self.metrics.log_event(now, "SPOOF", name, evidence.get("reason", ""))
        self.logger.warning("SPOOF/UNENROLLED from %s: %s", name, evidence)
        if host and self.trust_on:
            change = self.trust.add_event(TrustEvent(now, host.name, "E5_SPOOFING", dict(evidence, count=1)))
            if change:
                self._enforce(change)

    def _is_reachable(self, src, dst) -> bool:
        if not self.policy_on:
            return True
        return self.policy.any_allowed(src, dst)

    def _on_hidden(self, src, dst_ip):
        self.monitor.note_hidden_arp(src.name, dst_ip)

    # ====================================================== tier enforcement
    def _enforce(self, change):
        """Apply a tier change at the switches (design 7.4): purge, then new profile."""
        host = self.inventory.by_name(change.host)
        dps = list(self.datapaths.values())
        self.flows.purge_host(dps, host.host_id, (C_ALLOW, C_REV, C_DENY))
        edge = self.dp_of(host)
        if edge is not None:
            if change.new == Tier.QUARANTINED:
                self.flows.install_quarantine(edge, host, self.remediation[0].ip, self.remediation[1])
            elif change.old == Tier.QUARANTINED:
                self.flows.delete_by_cookie(edge, cookie(host.host_id, C_QUAR))
        self.metrics.log_tier_change(time.time(), change)
        self.logger.warning("TIER %s: %s -> %s (score %.1f)", change.host, change.old.name,
                            change.new.name, change.score)

    def override(self, name: str, tier):
        change = self.trust.override(name, tier, time.time())
        if change:
            self._enforce(change)
        return change

    def reload_policy(self):
        self.policy.reload()
        dps = list(self.datapaths.values())
        for t in (C_ALLOW, C_REV, C_DENY):
            self.flows.purge_type(dps, t)

    # =========================================================== monitoring
    def _loop(self):
        while True:
            hub.sleep(self.window_s - 0.5)
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(0.5)
            try:
                self._end_window(time.time())
            except Exception:  # keep the control loop alive no matter what
                self.logger.exception("window processing failed")

    def _end_window(self, now):
        feats = self.monitor.features(now)
        if self.trust_on:
            events = self.detectors.evaluate(now, feats)
            for change in self.trust.end_window(now, events):
                self._enforce(change)
            by_host = {}
            for e in events:
                by_host.setdefault(e.host, []).append(e.signal)
            for h in self.inventory.hosts:
                self.metrics.log_window(now, h, self.trust.score(h), self.trust.tier(h).name,
                                        self.trust.last_window_penalty[h], by_host.get(h, []))
        else:
            for h in self.inventory.hosts:
                self.metrics.log_window(now, h, 0, Tier.NORMAL.name, 0, [])
        cpu = self.proc.cpu_percent(None)
        mem = self.proc.memory_info().rss / 1e6
        pin_rate = self._pin_window / self.window_s
        self._pin_window = 0
        self.last_perf = {"cpu_pct": cpu, "mem_mb": mem, "packet_in_per_s": pin_rate,
                          "flow_count": self.monitor.total_flows(), "allow_rules": self.monitor.total_allow()}
        self.metrics.log_perf(now, cpu, mem, pin_rate, self.monitor.total_flows(), self.monitor.total_allow())

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def on_flow_stats(self, ev):
        dp = ev.msg.datapath
        buf = self._stats_buf.setdefault(dp.id, [])
        buf.extend(ev.msg.body)
        if not (ev.msg.flags & dp.ofproto.OFPMPF_REPLY_MORE):
            self.monitor.on_flow_stats(dp.id, buf, time.time())
            self._stats_buf[dp.id] = []

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def on_flow_removed(self, ev):
        host_id, ctype, _ = cookie_fields(ev.msg.cookie)
        if ctype == C_ALLOW:
            h = self.inventory.by_id(host_id)
            reason = {0: "IDLE_TIMEOUT", 1: "HARD_TIMEOUT", 2: "DELETED"}.get(ev.msg.reason, str(ev.msg.reason))
            self.metrics.log_event(time.time(), "LEASE_END", h.name if h else host_id, reason)

    # ================================================================ REST
    def api_hosts(self):
        now = time.time()
        snap = self.trust.snapshot(now)
        out = []
        for h in self.inventory.hosts.values():
            s = snap[h.name]
            out.append({"name": h.name, "zone": h.zone, "role": h.role, "ip": h.ip, "mac": h.mac,
                        "switch": h.switch, "score": s["score"] if self.trust_on else None,
                        "tier": self.tier_of(h.name).name, "override": s["override"],
                        "probation": s["probation"]})
        return out

    def api_stats(self):
        d = list(self.decision_us)
        return {"mode": self.mode, "uptime_s": round(time.time() - self.started),
                "switches": len(self.datapaths), "packet_in_total": self.n_packet_in,
                "decisions_total": self.n_decisions,
                "decision_us_mean": round(sum(d) / len(d), 1) if d else None,
                "decision_us_p95": round(sorted(d)[int(0.95 * (len(d) - 1))], 1) if d else None,
                **{k: round(v, 1) if isinstance(v, float) else v for k, v in self.last_perf.items()}}
