"""Shared data models for AEGIS-ZT (pure Python, no Ryu imports)."""
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Tier(IntEnum):
    """Trust tiers, ordered so that a higher value means more access."""
    QUARANTINED = 0
    RESTRICTED = 1
    NORMAL = 2
    TRUSTED = 3


@dataclass(frozen=True)
class Host:
    """An enrolled device from config/topology.yaml."""
    name: str
    zone: str
    role: str
    ip: str
    mac: str
    switch: str
    port: int
    host_id: int
    services: tuple = ()


@dataclass(frozen=True)
class Switch:
    name: str
    dpid: int
    role: str
    zone: Optional[str] = None


@dataclass
class Decision:
    """Result of a policy decision. Every decision carries its reason (explainability)."""
    action: str                     # "ALLOW" | "DENY"
    reason: str                     # rule id or e.g. "NO_MATCHING_RULE", "TIER_TOO_LOW"
    rule_id: Optional[str] = None
    idle_timeout: int = 0
    hard_timeout: int = 0
    icmp: bool = False

    @property
    def allowed(self) -> bool:
        return self.action == "ALLOW"


@dataclass
class TrustEvent:
    ts: float
    host: str
    signal: str                     # e.g. "E2_SCAN_FANOUT"
    evidence: dict = field(default_factory=dict)
    delta: float = 0.0


@dataclass
class TrustState:
    score: float = 75.0
    tier: Tier = Tier.NORMAL
    last_bad_ts: float = 0.0
    above_count: int = 0            # consecutive windows above the upgrade boundary
    probation_until: float = 0.0
    override: Optional[Tier] = None


@dataclass
class TierChange:
    host: str
    old: Tier
    new: Tier
    score: float
