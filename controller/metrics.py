"""Metrics logging for evaluation (Phase 5). Pure Python.

Files under the log directory (AEGIS_LOG_DIR, default logs/):
  decisions.csv    ts, src, dst, proto, port, action, reason, rule_id, decision_us
  tier_changes.csv ts, host, old, new, score
  windows.csv      ts, host, score, tier, penalty, signals   (one row per host per window)
  perf.csv         ts, cpu_pct, mem_mb, packet_in_per_s, flow_count, allow_rules
  events.csv       ts, kind, host, detail   (spoofing, hidden ARP, lease expiry...)
Spec: SDS_Phase2_Design.md section 13.3.
"""
import csv
import os
import threading


class MetricsLogger:
    HEADERS = {
        "decisions.csv": ["ts", "src", "dst", "proto", "port", "action", "reason", "rule_id", "decision_us"],
        "tier_changes.csv": ["ts", "host", "old", "new", "score"],
        "windows.csv": ["ts", "host", "score", "tier", "penalty", "signals"],
        "perf.csv": ["ts", "cpu_pct", "mem_mb", "packet_in_per_s", "flow_count", "allow_rules"],
        "events.csv": ["ts", "kind", "host", "detail"],
    }

    def __init__(self, log_dir: str):
        os.makedirs(log_dir, exist_ok=True)
        self.dir = log_dir
        self._lock = threading.Lock()
        self._files = {}
        for name, header in self.HEADERS.items():
            path = os.path.join(log_dir, name)
            new = not os.path.exists(path) or os.path.getsize(path) == 0
            f = open(path, "a", newline="")
            w = csv.writer(f)
            if new:
                w.writerow(header)
            self._files[name] = (f, w)

    def _write(self, name, row):
        with self._lock:
            f, w = self._files[name]
            w.writerow(row)
            f.flush()

    def log_decision(self, ts, src, dst, proto, port, decision, decision_us):
        self._write("decisions.csv", [round(ts, 3), src, dst, proto, port if port is not None else "",
                                      decision.action, decision.reason, decision.rule_id or "",
                                      round(decision_us, 1)])

    def log_tier_change(self, ts, change):
        self._write("tier_changes.csv", [round(ts, 3), change.host, change.old.name, change.new.name,
                                         round(change.score, 1)])

    def log_window(self, ts, host, score, tier, penalty, signals):
        self._write("windows.csv", [round(ts, 3), host, round(score, 1), tier, round(penalty, 1),
                                    "|".join(signals)])

    def log_perf(self, ts, cpu_pct, mem_mb, packet_in_per_s, flow_count, allow_rules):
        self._write("perf.csv", [round(ts, 3), round(cpu_pct, 1), round(mem_mb, 1),
                                 round(packet_in_per_s, 1), flow_count, allow_rules])

    def log_event(self, ts, kind, host, detail):
        self._write("events.csv", [round(ts, 3), kind, host, detail])
