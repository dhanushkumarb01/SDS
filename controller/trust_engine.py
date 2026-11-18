"""Trust Engine: scores, tiers, hysteresis, probation, overrides, ledger (pure Python).

Spec: SDS_Phase2_Design.md section 7.
  * score in [0, 100], start = initial_score (NORMAL)
  * per window: penalty = sum over signals of min(cap, weight * count)
  * recovery r per window once quiet_period_s has passed without penalties
  * downgrade immediately; upgrade one tier at a time, only after the score
    has stayed >= next boundary + margin for upgrade_windows windows
  * after quarantine: probation (score ceiling) for probation_s
  * admin override pins the effective tier
  * every change is appended to the ledger (JSONL) with its evidence
"""
import json
import threading
from collections import deque
from typing import Dict, List, Optional

from models import Tier, TierChange, TrustEvent, TrustState

IMMEDIATE = {"E5_SPOOFING"}


class TrustEngine:
    def __init__(self, settings: dict, host_names: List[str], ledger_path: Optional[str]):
        self.cfg = settings
        self.signals = settings["signals"]
        self.bounds = {Tier[k]: v for k, v in settings["tiers"].items()}
        self.state: Dict[str, TrustState] = {}
        for h in host_names:
            s = TrustState(score=float(settings["initial_score"]))
            s.tier = self.tier_for(s.score)
            self.state[h] = s
        self.ledger_path = ledger_path
        self.recent = deque(maxlen=1000)        # in-memory ledger for the REST API
        self._seq = 0
        self._lock = threading.Lock()
        self._applied: Dict[str, Dict[str, float]] = {h: {} for h in host_names}  # penalties already applied this window
        self.last_window_penalty: Dict[str, float] = {h: 0.0 for h in host_names}

    # ---- helpers -------------------------------------------------------
    def tier_for(self, score: float) -> Tier:
        for t in (Tier.TRUSTED, Tier.NORMAL, Tier.RESTRICTED):
            if score >= self.bounds[t]:
                return t
        return Tier.QUARANTINED

    def tier(self, host: str) -> Tier:
        s = self.state[host]
        return s.override if s.override is not None else s.tier

    def score(self, host: str) -> float:
        return self.state[host].score

    def _penalty(self, host: str, signal: str, count: float) -> float:
        cfg = self.signals[signal]
        already = self._applied[host].get(signal, 0.0)
        p = min(cfg["cap"], cfg["weight"] * count + already) - already
        p = max(0.0, p)
        self._applied[host][signal] = already + p
        return p

    def _log(self, entry: dict):
        self._seq += 1
        entry = {"seq": self._seq, **entry}
        self.recent.append(entry)
        if self.ledger_path:
            with open(self.ledger_path, "a") as f:
                f.write(json.dumps(entry) + "\n")

    def _set_tier(self, host: str, new: Tier, now: float, reason: str) -> Optional[TierChange]:
        s = self.state[host]
        old_eff = self.tier(host)
        if new == s.tier:
            return None
        if s.tier == Tier.QUARANTINED and new > Tier.QUARANTINED:
            s.probation_until = now + self.cfg["probation_s"]
        s.tier = new
        s.above_count = 0
        new_eff = self.tier(host)
        self._log({"ts": now, "host": host, "signal": "TIER_CHANGE", "evidence": {"reason": reason},
                   "delta": 0, "score_after": round(s.score, 1),
                   "tier_before": old_eff.name, "tier_after": new_eff.name})
        return TierChange(host, old_eff, new_eff, s.score) if new_eff != old_eff else None

    def _apply_penalties(self, host: str, events: List[TrustEvent], now: float) -> float:
        s = self.state[host]
        total = 0.0
        for ev in events:
            p = self._penalty(host, ev.signal, ev.evidence.get("count", 1))
            if p <= 0:
                continue
            before = s.score
            s.score = max(0.0, s.score - p)
            total += p
            ev.delta = -p
            self._log({"ts": now, "host": host, "signal": ev.signal, "evidence": ev.evidence,
                       "delta": -round(p, 1), "score_before": round(before, 1),
                       "score_after": round(s.score, 1), "tier_before": self.tier(host).name})
        if total > 0:
            s.last_bad_ts = now
            s.above_count = 0
        return total

    # ---- public API ----------------------------------------------------
    def add_event(self, event: TrustEvent) -> Optional[TierChange]:
        """Apply a severe signal (E5 spoofing) immediately; returns a tier change if any."""
        with self._lock:
            if event.host not in self.state:
                return None
            self._apply_penalties(event.host, [event], event.ts)
            new = self.tier_for(self.state[event.host].score)
            if new < self.state[event.host].tier:
                return self._set_tier(event.host, new, event.ts, event.signal)
            return None

    def end_window(self, now: float, events: List[TrustEvent]) -> List[TierChange]:
        """Apply this window's penalties and recovery; update tiers with hysteresis."""
        changes: List[TierChange] = []
        with self._lock:
            by_host: Dict[str, List[TrustEvent]] = {}
            for ev in events:
                if ev.host in self.state:
                    by_host.setdefault(ev.host, []).append(ev)
            for host, s in self.state.items():
                self._apply_penalties(host, by_host.get(host, []), now)
                # includes immediate (E5) penalties applied earlier in this window
                self.last_window_penalty[host] = sum(self._applied[host].values())
                if self.last_window_penalty[host] == 0 \
                        and now - s.last_bad_ts >= self.cfg["quiet_period_s"]:
                    ceiling = self.cfg["probation_ceiling"] if now < s.probation_until else 100.0
                    if s.score < ceiling:
                        before = s.score
                        s.score = min(ceiling, s.score + self.cfg["recovery_per_window"])
                        self._log({"ts": now, "host": host, "signal": "RECOVERY", "evidence": {},
                                   "delta": round(s.score - before, 1), "score_before": round(before, 1),
                                   "score_after": round(s.score, 1), "tier_before": self.tier(host).name})
                ch = self._update_tier(host, now)
                if ch:
                    changes.append(ch)
                self._applied[host] = {}
        return changes

    def _update_tier(self, host: str, now: float) -> Optional[TierChange]:
        s = self.state[host]
        target = self.tier_for(s.score)
        if target < s.tier:
            return self._set_tier(host, target, now, "SCORE_BELOW_%d" % self.bounds[s.tier])
        if target > s.tier:
            nxt = Tier(s.tier + 1)
            if s.score >= self.bounds[nxt] + self.cfg["upgrade_margin"]:
                s.above_count += 1
                if s.above_count >= self.cfg["upgrade_windows"]:
                    return self._set_tier(host, nxt, now, "HYSTERESIS_MET")
            else:
                s.above_count = 0
        else:
            s.above_count = 0
        return None

    def override(self, host: str, tier: Optional[Tier], now: float) -> Optional[TierChange]:
        """Pin (or clear with None) a host's effective tier. Logged in the ledger."""
        with self._lock:
            s = self.state[host]
            old = self.tier(host)
            s.override = tier
            new = self.tier(host)
            self._log({"ts": now, "host": host, "signal": "ADMIN_OVERRIDE",
                       "evidence": {"pinned": tier.name if tier is not None else None},
                       "delta": 0, "score_after": round(s.score, 1),
                       "tier_before": old.name, "tier_after": new.name})
            return TierChange(host, old, new, s.score) if new != old else None

    def snapshot(self, now: float) -> dict:
        return {h: {"score": round(s.score, 1), "tier": self.tier(h).name,
                    "base_tier": s.tier.name,
                    "override": s.override.name if s.override is not None else None,
                    "probation": s.probation_until > now}
                for h, s in self.state.items()}

    def events_since(self, seq: int) -> list:
        return [e for e in list(self.recent) if e["seq"] > seq]
