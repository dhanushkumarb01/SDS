#!/usr/bin/env python3
"""Turn results/raw/* into summary tables (SDS_Phase2_Design.md section 13.3).

  python eval/compute_metrics.py        (inside ~/aegis-venv)

Writes results/summary/: runs.csv, by_scenario.csv, detection.csv, perf.csv,
scale.csv and summary.md (human-readable tables for the report).

Ground truth for detection (per host, per 5 s window):
  malicious = the scenario's attacker, in a window overlapping the attack
              (plus one window of reporting lag after it ends)
  benign    = every other host-window (all windows of S6, which has no attacker)
  excluded  = the attacker's windows outside the attack (warm-up / cool-down),
              where a low trust score is the intended after-effect
  predicted positive = a penalty was applied in that window, or the host is in the
                       RESTRICTED/QUARANTINED tier at the window's end (design 13.3)
"""
import glob
import json
import os
import re
import statistics as st

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "results", "raw")
OUT = os.path.join(ROOT, "results", "summary")
W = 5.0


def read_csv(path):
    return pd.read_csv(path) if os.path.exists(path) and os.path.getsize(path) > 0 else pd.DataFrame()


def ping_stats(path):
    if not os.path.exists(path):
        return None, None
    txt = open(path).read()
    loss = re.search(r"([\d.]+)% packet loss", txt)
    rtt = re.search(r"= [\d.]+/([\d.]+)/", txt)
    return (float(loss.group(1)) if loss else None, float(rtt.group(1)) if rtt else None)


def open_ports(gnmap):
    if not os.path.exists(gnmap):
        return 0
    n = 0
    for line in open(gnmap):
        if "Ports:" in line:
            n += len(re.findall(r"\d+/open/", line))
    return n


def attack_run(d):
    meta = json.load(open(os.path.join(d, "scenario.json")))
    start, end, atk = meta["attack_start"], meta["attack_end"], meta["attacker"]
    r = {"mode": meta["mode"], "scenario": meta["scenario"], "rep": meta["rep"], "attacker": atk}

    # ---- detection confusion matrix
    win = read_csv(os.path.join(d, "windows.csv"))
    tp = fp = tn = fn = 0
    for row in win.itertuples():
        # design 13.3: predicted malicious = a penalty was applied OR the host sits in a
        # restricted/quarantined tier (a contained attacker stops generating new penalties)
        pos = row.penalty > 0 or row.tier in ("RESTRICTED", "QUARANTINED")
        if atk and row.host == atk:
            if row.ts > start and row.ts - W < end + W:
                tp += pos
                fn += not pos
            continue
        fp += pos
        tn += not pos
    r.update(tp=tp, fp=fp, tn=tn, fn=fn)

    # ---- containment timing
    r["ttd_s"] = r["ttr_s"] = r["ttc_s"] = None
    if atk:
        ledger = os.path.join(d, "trust_ledger.jsonl")
        if os.path.exists(ledger):
            hits = [e["ts"] for e in map(json.loads, open(ledger))
                    if e["host"] == atk and e.get("delta", 0) < 0 and e["ts"] >= start]
            r["ttd_s"] = round(min(hits) - start, 2) if hits else None
        tc = read_csv(os.path.join(d, "tier_changes.csv"))
        if not tc.empty:
            mine = tc[(tc.host == atk) & (tc.ts >= start)]
            rq = mine[mine.new.isin(["RESTRICTED", "QUARANTINED"])]
            q = mine[mine.new == "QUARANTINED"]
            r["ttr_s"] = round(rq.ts.min() - start, 2) if not rq.empty else None
            r["ttc_s"] = round(q.ts.min() - start, 2) if not q.empty else None
        # collateral: other hosts that lost a tier during the run
        if not tc.empty:
            others = tc[(tc.host != atk) & tc.new.isin(["RESTRICTED", "QUARANTINED"])]
            r["collateral_hosts"] = others.host.nunique()
        else:
            r["collateral_hosts"] = 0
    else:
        tc = read_csv(os.path.join(d, "tier_changes.csv"))
        r["collateral_hosts"] = 0 if tc.empty else tc[tc.new.isin(["RESTRICTED", "QUARANTINED"])].host.nunique()

    # ---- blast radius / attack success
    sid = meta["scenario"]
    r["open_services_found"] = open_ports(os.path.join(d, "scan.gnmap")) if sid in ("S1", "S5") else None
    if sid == "S2":
        lat = os.path.join(d, "lateral.txt")
        lines = [l.split() for l in open(lat)] if os.path.exists(lat) else []
        r["targets_reached"] = len({l[1] for l in lines if len(l) == 2})
        r["successful_connections"] = len(lines)
        r["last_success_s"] = round(max(float(l[0]) for l in lines) - start, 1) if lines else 0
    if sid == "S3":
        av = os.path.join(d, "availability.txt")
        if os.path.exists(av):
            ok, n = map(int, open(av).read().split())
            r["collector_availability_pct"] = round(100 * ok / n, 1) if n else None
    if sid == "S4":
        sp = os.path.join(d, "spoof_delivered.txt")
        r["spoofed_pkts_delivered"] = sum(1 for l in open(sp) if "10.0.2.20" in l) if os.path.exists(sp) else 0
        r["arp_poisoned_victims"] = len(meta.get("poisoned_victims", []))
    if sid == "S6":
        ip = os.path.join(d, "iperf_s6.json")
        try:
            r["bulk_throughput_mbps"] = round(json.load(open(ip))["end"]["sum_received"]["bits_per_second"] / 1e6)
        except Exception:
            r["bulk_throughput_mbps"] = None

    ra = meta.get("attacker_retains_access")
    r["retains_access_pct"] = None if ra is None else 100.0 * bool(ra)

    # ---- legitimate user + controller cost during the attack
    r["legit_loss_pct"], r["legit_rtt_ms"] = ping_stats(os.path.join(d, "legit_ping.txt"))
    perf = read_csv(os.path.join(d, "perf.csv"))
    if not perf.empty:
        p = perf[(perf.ts >= start) & (perf.ts <= end + W)]
        r["ctrl_cpu_mean"] = round(p.cpu_pct.mean(), 1) if not p.empty else None
        r["ctrl_cpu_max"] = round(p.cpu_pct.max(), 1) if not p.empty else None
        r["packet_in_per_s_max"] = round(p.packet_in_per_s.max(), 1) if not p.empty else None
        r["flows_max"] = int(perf.flow_count.max())
    dec = read_csv(os.path.join(d, "decisions.csv"))
    r["decisions"] = len(dec)
    r["decision_us_median"] = round(dec.decision_us.median(), 1) if not dec.empty else None
    return r


def rates(tp, fp, tn, fn):
    P = tp + fn
    N = fp + tn
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / P if P else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else (0.0 if P else None)
    return {"accuracy": (tp + tn) / (P + N) if P + N else None, "precision": prec, "recall": rec,
            "f1": f1, "fpr": fp / N if N else None, "fnr": fn / P if P else None}


def fmt(v, nd=2):
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return "–"
    return ("%%.%df" % nd) % v if isinstance(v, float) else str(v)


def md_table(df, cols, nd=2):
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for _, row in df.iterrows():
        lines.append("| " + " | ".join(fmt(row[c], nd) for c in cols) + " |")
    return "\n".join(lines)


def main():
    os.makedirs(OUT, exist_ok=True)
    md = ["# AEGIS-ZT evaluation summary", ""]

    # ------------------------------------------------------------ attacks
    runs = [attack_run(d) for d in sorted(glob.glob(os.path.join(RAW, "attacks", "*")))
            if os.path.exists(os.path.join(d, "scenario.json"))]
    if runs:
        df = pd.DataFrame(runs)
        df.to_csv(os.path.join(OUT, "runs.csv"), index=False)
        reps = df.rep.nunique()
        md += ["Attack runs: %d (%d repetitions per mode × scenario). Times are seconds after attack start; "
               "values are means over repetitions." % (len(df), reps), ""]

        num = [c for c in df.columns if c not in ("mode", "scenario", "rep", "attacker")]
        g = df.groupby(["scenario", "mode"])[num]
        mean, std = g.mean(numeric_only=True), g.std(numeric_only=True)
        by = mean.round(2).join(std.add_suffix("_std").round(2)).reset_index()
        by.to_csv(os.path.join(OUT, "by_scenario.csv"), index=False)

        # detection per mode x scenario (pooled confusion matrix)
        det = []
        for (m, s), x in df.groupby(["mode", "scenario"]):
            c = x[["tp", "fp", "tn", "fn"]].sum()
            det.append({"mode": m, "scenario": s, **c.to_dict(), **rates(*c)})
        for m, x in df.groupby("mode"):
            c = x[["tp", "fp", "tn", "fn"]].sum()
            det.append({"mode": m, "scenario": "ALL", **c.to_dict(), **rates(*c)})
        det = pd.DataFrame(det)
        det.to_csv(os.path.join(OUT, "detection.csv"), index=False)

        md += ["## Detection (per host-window, pooled over repetitions)", "",
               md_table(det.sort_values(["mode", "scenario"]),
                        ["mode", "scenario", "tp", "fp", "tn", "fn", "accuracy", "precision", "recall", "f1",
                         "fpr", "fnr"], 3), ""]

        md += ["## Containment (AEGIS-ZT, mode B2)", ""]
        b2 = by[by["mode"] == "B2"]
        md += [md_table(b2, ["scenario", "ttd_s", "ttd_s_std", "ttr_s", "ttc_s", "ttc_s_std",
                             "collateral_hosts", "legit_loss_pct"], 1), ""]

        md += ["## Blast radius and attack success by mode", ""]
        rows = []
        for s, label, col in [("S1", "attacker still has its normal access after attack (% runs)", "retains_access_pct"),
                              ("S2", "attacker still has its normal access after attack (% runs)", "retains_access_pct"),
                              ("S3", "attacker still has its normal access after attack (% runs)", "retains_access_pct"),
                              ("S4", "attacker still has its normal access after attack (% runs)", "retains_access_pct"),
                              ("S5", "attacker still has its normal access after attack (% runs)", "retains_access_pct"),
                              ("S1", "open services found by scan", "open_services_found"),
                              ("S5", "open services found by slow scan", "open_services_found"),
                              ("S2", "targets reached by lateral movement", "targets_reached"),
                              ("S2", "successful lateral connections", "successful_connections"),
                              ("S3", "collector availability for real sensor (%)", "collector_availability_pct"),
                              ("S4", "spoofed packets delivered to web1", "spoofed_pkts_delivered"),
                              ("S4", "users with poisoned ARP cache", "arp_poisoned_victims"),
                              ("S6", "legit bulk upload throughput (Mbit/s)", "bulk_throughput_mbps"),
                              ("S6", "hosts wrongly restricted (false alarms)", "collateral_hosts")]:
            if col not in by.columns:
                continue
            vals = {m: by[(by.scenario == s) & (by["mode"] == m)][col] for m in ("B0", "B1", "B2")}
            rows.append({"scenario": s, "metric": label,
                         **{m: (v.iloc[0] if len(v) else None) for m, v in vals.items()}})
        br = pd.DataFrame(rows)
        br.to_csv(os.path.join(OUT, "blast_radius.csv"), index=False)
        md += [md_table(br, ["scenario", "metric", "B0", "B1", "B2"], 1), ""]

        md += ["## Legitimate user (u2 → web1 ping) during attacks: loss %", ""]
        lg = by.pivot(index="scenario", columns="mode", values="legit_loss_pct").reset_index()
        md += [md_table(lg, ["scenario"] + [m for m in ("B0", "B1", "B2") if m in lg.columns], 1), ""]

    # ------------------------------------------------------------ performance
    perf = []
    for f in sorted(glob.glob(os.path.join(RAW, "perf", "*", "perf.json"))):
        j = json.load(open(f))
        firsts = [v for v in j.get("first_rtt_ms", []) if v is not None]
        steady = j.get("steady_rtts_ms", [])[1:]
        perf.append({"mode": j["mode"], "rep": j["rep"],
                     "first_rtt_ms": st.mean(firsts) if firsts else None,
                     "steady_rtt_ms": st.median(steady) if steady else None,
                     "throughput_mbps": j.get("throughput_mbps"),
                     "decision_us_mean": j.get("stats_end", {}).get("decision_us_mean")})
    if perf:
        pf = pd.DataFrame(perf)
        pf.to_csv(os.path.join(OUT, "perf_runs.csv"), index=False)
        agg = pf.groupby("mode").agg(["mean", "std"]).drop(columns="rep")
        agg.columns = ["%s_%s" % c for c in agg.columns]
        agg = agg.reset_index()
        agg.to_csv(os.path.join(OUT, "perf.csv"), index=False)
        b0 = agg[agg["mode"] == "B0"]["throughput_mbps_mean"]
        if len(b0):
            agg["throughput_vs_B0_pct"] = 100 * agg["throughput_mbps_mean"] / b0.iloc[0]
        md += ["## Performance overhead", "",
               md_table(agg, [c for c in ["mode", "first_rtt_ms_mean", "steady_rtt_ms_mean", "throughput_mbps_mean",
                                          "throughput_vs_B0_pct", "decision_us_mean_mean"] if c in agg.columns], 2),
               "", "first_rtt = first packet of a brand-new flow (ARP + controller decision + rule install); "
               "steady = later packets switched in the data plane.", ""]

    # ------------------------------------------------------------ scalability
    sc = []
    for d in sorted(glob.glob(os.path.join(RAW, "scale", "*"))):
        f = os.path.join(d, "scale.json")
        if not os.path.exists(f):
            continue
        j = json.load(open(f))
        p = read_csv(os.path.join(d, "perf.csv"))
        dec = read_csv(os.path.join(d, "decisions.csv"))
        sc.append({"hosts": j["hosts"], "rep": j["rep"],
                   "decision_us_median": dec.decision_us.median() if not dec.empty else None,
                   "decision_us_p95": dec.decision_us.quantile(0.95) if not dec.empty else None,
                   "decisions": len(dec),
                   "cpu_mean": p.cpu_pct.mean() if not p.empty else None,
                   "mem_mb": p.mem_mb.max() if not p.empty else None,
                   "flows_max": p.flow_count.max() if not p.empty else None,
                   "false_alarms": (read_csv(os.path.join(d, "windows.csv")).penalty > 0).sum()})
    if sc:
        sf = pd.DataFrame(sc)
        agg = sf.groupby("hosts").mean(numeric_only=True).drop(columns="rep").reset_index()
        agg.to_csv(os.path.join(OUT, "scale.csv"), index=False)
        md += ["## Scalability (B2, benign traffic, 45 s)", "",
               md_table(agg, ["hosts", "decisions", "decision_us_median", "decision_us_p95", "cpu_mean", "mem_mb",
                              "flows_max", "false_alarms"], 1), ""]

    with open(os.path.join(OUT, "summary.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
