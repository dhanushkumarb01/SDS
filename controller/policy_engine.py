"""Policy Engine: zone policy decisions (pure Python, no Ryu imports).

Loads config/policy.yaml and answers "may src reach dst on proto/port right
now, given src's trust tier?" with an explainable Decision.
Spec: SDS_Phase2_Design.md section 6.3 (decision order) and 6.4 (tier profiles).
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

import yaml

from models import Decision, Host, Tier

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


@dataclass
class Rule:
    id: str
    desc: str
    src: dict
    dst: dict
    proto: str
    port: Optional[int]
    icmp: bool
    essential: bool
    min_tier: Tier
    schedule: Optional[dict] = None
    raw: dict = field(default_factory=dict)


def _as_list(v):
    return v if isinstance(v, list) else [v]


def _selector_match(sel: dict, host: Host) -> bool:
    if "host" in sel:
        return host.name in _as_list(sel["host"])
    if "zone" in sel:
        zones = _as_list(sel["zone"])
        return "any" in zones or host.zone in zones
    return False


def _in_schedule(sched: dict, now: datetime) -> bool:
    if DAYS[now.weekday()] not in sched.get("days", DAYS):
        return False
    hhmm = now.strftime("%H:%M")
    return sched.get("start", "00:00") <= hhmm <= sched.get("end", "23:59")


class PolicyEngine:
    def __init__(self, policy_path: str, inventory, leases: dict):
        """leases: {"NORMAL": [idle, hard], ...} from trust.yaml"""
        self.path = policy_path
        self.inv = inventory
        self.leases = leases
        self.rules: List[Rule] = []
        self.roles: dict = {}
        self.reload()

    def reload(self) -> None:
        with open(self.path) as f:
            cfg = yaml.safe_load(f)
        if cfg.get("default_action", "deny") != "deny":
            raise ValueError("AEGIS-ZT requires default_action: deny")
        services = cfg.get("services", {})
        schedules = cfg.get("schedules", {})
        rules = []
        for r in cfg.get("rules", []):
            svc = services[r["service"]]
            sched = r.get("schedule")
            rules.append(Rule(
                id=r["id"], desc=r.get("desc", ""), src=r["from"], dst=r["to"],
                proto=svc["proto"], port=svc.get("port"), icmp=bool(r.get("icmp", False)),
                essential=bool(r.get("essential", False)),
                min_tier=Tier[r.get("min_tier", "NORMAL")],
                schedule=schedules[sched] if sched else None, raw=r))
        self.rules = rules
        self.roles = cfg.get("roles", {})

    def lease_for(self, tier: Tier):
        idle, hard = self.leases[tier.name]
        return int(idle), int(hard)

    def _matching_rule(self, src: Host, dst: Host, proto: str, dst_port: Optional[int]) -> Optional[Rule]:
        for r in self.rules:
            if not (_selector_match(r.src, src) and _selector_match(r.dst, dst)):
                continue
            if proto == "icmp":
                if r.icmp:
                    return r
            elif proto == r.proto and dst_port == r.port:
                return r
        return None

    def decide(self, src: Optional[Host], dst: Optional[Host], proto: str,
               dst_port: Optional[int], tier: Tier, now: Optional[datetime] = None) -> Decision:
        """Design 6.3: unenrolled -> deny; first matching rule, then tier,
        schedule and essential checks; no rule -> deny (default)."""
        if src is None or dst is None:
            return Decision("DENY", "UNENROLLED")
        rule = self._matching_rule(src, dst, proto, dst_port)
        if rule is None:
            return Decision("DENY", "NO_MATCHING_RULE")
        if tier < rule.min_tier:
            return Decision("DENY", "TIER_TOO_LOW", rule.id)
        if rule.schedule and not _in_schedule(rule.schedule, now or datetime.now()):
            return Decision("DENY", "OUT_OF_SCHEDULE", rule.id)
        if tier == Tier.RESTRICTED and not rule.essential:
            return Decision("DENY", "NOT_ESSENTIAL", rule.id)
        idle, hard = self.lease_for(tier)
        return Decision("ALLOW", rule.id, rule.id, idle, hard, icmp=(proto == "icmp"))

    def reply_rule(self, src: Host, dst: Host, proto: str, src_port: Optional[int]) -> Optional[Rule]:
        """Is a packet src -> dst (sent FROM src_port) a reply to a request dst -> src
        that some rule covers (ignoring tier)? Used for stateless reply recognition."""
        return self._matching_rule(dst, src, proto, None if proto == "icmp" else src_port)

    def any_allowed(self, src: Host, dst: Host) -> bool:
        """May src learn that dst exists (proxy ARP)? True if any rule links the
        two in either direction (the responder must also resolve the initiator)."""
        for r in self.rules:
            if _selector_match(r.src, src) and _selector_match(r.dst, dst):
                return True
            if _selector_match(r.src, dst) and _selector_match(r.dst, src):
                return True
        return False

    def initiates_ok(self, src: Host, decision: Decision) -> bool:
        """Role check for detector E4. Roles without an entry are unconstrained."""
        role = self.roles.get(src.role)
        if role is None:
            return True
        return decision.allowed and decision.rule_id in role.get("initiates", [])

    def describe(self) -> list:
        return [{"id": r.id, "desc": r.desc, "from": r.src, "to": r.dst, "proto": r.proto,
                 "port": r.port, "icmp": r.icmp, "essential": r.essential,
                 "min_tier": r.min_tier.name, "schedule": r.raw.get("schedule")} for r in self.rules]
