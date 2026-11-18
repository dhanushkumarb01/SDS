#!/usr/bin/env python3
"""Report/PPT figures from results/ (SDS_Phase2_Design.md section 13.4).

  python eval/plot_results.py      (inside ~/aegis-venv, after compute_metrics.py)

Writes PNGs (200 dpi) to results/figures/. Colours: one fixed hue per mode
(validated categorical palette), status tints for trust tiers, ink for text.
"""
import glob
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "results", "raw")
SUM = os.path.join(ROOT, "results", "summary")
FIG = os.path.join(ROOT, "results", "figures")

MODES = ["B0", "B1", "B2"]
MODE_LABEL = {"B0": "B0 flat network", "B1": "B1 static zones", "B2": "B2 AEGIS-ZT"}
MODE_C = {"B0": "#2a78d6", "B1": "#eb6834", "B2": "#1baf7a"}
S1, S2, S3 = "#2a78d6", "#eb6834", "#1baf7a"           # categorical slots 1-3
INK, INK2, GRID, SURF = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
TIER_BANDS = [(85, 100, "#0ca30c", "TRUSTED"), (70, 85, "#0ca30c", "NORMAL"),
              (40, 70, "#fab219", "RESTRICTED"), (0, 40, "#d03b3b", "QUARANTINED")]

plt.rcParams.update({
    "figure.facecolor": SURF, "axes.facecolor": SURF, "savefig.facecolor": SURF,
    "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "axes.titlecolor": INK, "axes.titlesize": 11, "axes.titleweight": "bold", "axes.labelsize": 9,
    "xtick.labelsize": 8.5, "ytick.labelsize": 8.5, "font.size": 9, "legend.fontsize": 8.5,
    "legend.frameon": False, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
})


def save(fig, name, note=None):
    if note:
        fig.text(0.01, -0.06, note, fontsize=7.5, color=INK2, ha="left", va="top")
    fig.savefig(os.path.join(FIG, name), dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("  wrote", name)


def _ok(v):
    return v is not None and pd.notna(v)


def bars(ax, labels, values, colors, fmt="%.0f", errs=None):
    x = range(len(labels))
    heights = [v if _ok(v) else 0 for v in values]
    if errs is not None:
        errs = [e if _ok(e) else 0 for e in errs]
    b = ax.bar(x, heights, color=colors, width=0.62, yerr=errs, capsize=3 if errs is not None else 0,
               error_kw={"elinewidth": 1, "ecolor": INK2}, edgecolor=SURF, linewidth=2)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    top = max([v + (errs[i] if errs is not None else 0) for i, v in enumerate(values) if _ok(v)] + [1])
    for i, (rect, v) in enumerate(zip(b, values)):
        lift = (errs[i] if errs is not None else 0)
        ax.text(rect.get_x() + rect.get_width() / 2, rect.get_height() + lift + top * 0.025,
                fmt % v if _ok(v) else "n/a", ha="center", va="bottom", fontsize=8.5, color=INK)
    ax.set_ylim(0, top * 1.18)
    ax.grid(axis="x", visible=False)


def tier_bands(ax):
    for lo, hi, c, name in TIER_BANDS:
        ax.axhspan(lo, hi, color=c, alpha=0.07, lw=0)
    for y in (85, 70, 40):
        ax.axhline(y, color=INK2, lw=0.5, ls=(0, (2, 3)))
    for lo, hi, _, name in TIER_BANDS:
        ax.text(1.01, (lo + hi) / 2, name, transform=ax.get_yaxis_transform(), fontsize=7, color=INK2,
                va="center")


def run_dir(kind, mode, sid, rep=1):
    d = os.path.join(RAW, kind, "%s_%s_r%d" % (mode, sid, rep))
    return d if os.path.exists(os.path.join(d, "scenario.json")) else None


# --------------------------------------------------------------------------- F1
def fig_trust_timeline():
    panels = [("S1", "Fast port scan (cam1)", "cam1", [("u2", "bystander u2", S2)]),
              ("S5", "Low-and-slow scan (u3)", "u3", [("u2", "bystander u2", S2)]),
              ("S3", "SYN flood (cam2 → col1)", "cam2", [("col1", "victim col1", S3)])]
    avail = [p for p in panels if run_dir("attacks", "B2", p[0])]
    if not avail:
        return
    fig, axes = plt.subplots(1, len(avail), figsize=(4.6 * len(avail), 3.4), sharey=True, squeeze=False,
                             gridspec_kw={"wspace": 0.55})
    axes = axes[0]
    for ax, (sid, title, atk, others) in zip(axes, avail):
        d = run_dir("attacks", "B2", sid)
        meta = json.load(open(os.path.join(d, "scenario.json")))
        w = pd.read_csv(os.path.join(d, "windows.csv"))
        w["t"] = w.ts - meta["attack_start"]
        tier_bands(ax)
        ax.axvspan(0, meta["attack_end"] - meta["attack_start"], color=INK2, alpha=0.08, lw=0)
        ax.text(1, 95, "attack", fontsize=7.5, color=INK2)
        for host, label, c in others:
            h = w[w.host == host]
            ax.plot(h.t, h.score, color=c, lw=2, label=label)
        h = w[w.host == atk]
        ax.plot(h.t, h.score, color=S1, lw=2, label="attacker " + atk, marker="o", ms=4)
        ax.set_title(title, loc="left")
        ax.set_xlabel("seconds since attack start")
        ax.set_ylim(0, 102)
        ax.legend(loc="center left", bbox_to_anchor=(0, 0.55))
    axes[0].set_ylabel("trust score")
    save(fig, "F1_trust_timeline.png", "AEGIS-ZT (B2), repetition 1. Shaded = attack period. "
                                       "Score sampled every 5 s window.")


# --------------------------------------------------------------------------- F2
def fig_blast_radius(by):
    specs = [("S1", "open_services_found", "Services found by a port scan", "%.0f"),
             ("S2", "successful_connections", "Successful lateral connections", "%.0f"),
             ("S4", "spoofed_pkts_delivered", "Spoofed packets delivered", "%.0f"),
             ("S4", "arp_poisoned_victims", "Users whose ARP cache\nwas poisoned", "%.0f")]
    specs = [s for s in specs if s[1] in by.columns]
    if not specs:
        return
    fig, axes = plt.subplots(1, len(specs), figsize=(3.3 * len(specs), 3.3), squeeze=False)
    for ax, (sid, col, title, fmt) in zip(axes[0], specs):
        sub = by[by.scenario == sid].set_index("mode")
        vals = [sub[col].get(m) if m in sub.index else None for m in MODES]
        errs = [sub[col + "_std"].get(m) if m in sub.index and col + "_std" in sub else 0 for m in MODES]
        bars(ax, ["B0\nflat", "B1\nstatic", "B2\nAEGIS-ZT"], vals, [MODE_C[m] for m in MODES], fmt,
             [0 if pd.isna(e) else e for e in errs])
        ax.set_title(title, loc="left", fontsize=9.5)
    fig.subplots_adjust(wspace=0.35)
    save(fig, "F2_blast_radius.png", "Mean of repetitions; error bars = standard deviation. Lower is better. "
                                     "S1/S2/S4 are 3 repetitions each.")


# --------------------------------------------------------------------------- F3
def fig_containment(by):
    b2 = by[by["mode"] == "B2"].set_index("scenario")
    sids = [s for s in ["S1", "S2", "S3", "S4", "S5"] if s in b2.index]
    if not sids:
        return
    fig, ax = plt.subplots(figsize=(7, 3.4))
    x = range(len(sids))
    for off, col, label, c in ((-0.2, "ttd_s", "time to detect", S1), (0.2, "ttc_s", "time to quarantine", S2)):
        vals = [b2[col].get(s) for s in sids]
        errs = [b2.get(col + "_std", pd.Series()).get(s, 0) for s in sids]
        errs = [0 if pd.isna(e) else e for e in errs]
        r = ax.bar([i + off for i in x], [0 if pd.isna(v) else v for v in vals], width=0.38, color=c, label=label,
                   yerr=errs, capsize=3, error_kw={"elinewidth": 1, "ecolor": INK2}, edgecolor=SURF, linewidth=2)
        for rect, v in zip(r, vals):
            ax.text(rect.get_x() + rect.get_width() / 2, rect.get_height() + 0.6,
                    "n/a" if pd.isna(v) else "%.1f" % v, ha="center", fontsize=8, color=INK)
    names = {"S1": "S1 scan", "S2": "S2 lateral", "S3": "S3 SYN flood", "S4": "S4 spoofing", "S5": "S5 slow scan"}
    ax.set_xticks(list(x))
    ax.set_xticklabels([names[s] for s in sids])
    ax.set_ylabel("seconds after attack start")
    ax.set_title("How fast AEGIS-ZT detects and contains each attack", loc="left")
    ax.grid(axis="x", visible=False)
    ax.legend(loc="upper left")
    save(fig, "F3_containment_time.png", "B2, mean ± std over repetitions. Monitoring window = 5 s; "
                                         "spoofing is penalised immediately.")


# --------------------------------------------------------------------------- F4
def fig_detection():
    p = os.path.join(SUM, "detection.csv")
    if not os.path.exists(p):
        return
    d = pd.read_csv(p)
    d = d[(d["mode"] == "B2")]
    order = [s for s in ["S1", "S2", "S3", "S4", "S5", "S6", "ALL"] if s in set(d.scenario)]
    d = d.set_index("scenario").loc[order]
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.2))
    recall = [v * 100 if pd.notna(v) else None for v in d.recall]
    fpr = [v * 100 if pd.notna(v) else None for v in d.fpr]
    bars(axes[0], order, recall, [S1] * len(order), "%.0f%%")
    axes[0].set_title("Recall: attack windows detected (%)", loc="left", fontsize=10)
    axes[0].set_ylim(0, 115)
    bars(axes[1], order, fpr, [S2] * len(order), "%.1f%%")
    axes[1].set_title("False-positive rate: benign windows flagged (%)", loc="left", fontsize=10)
    top = max([f for f in fpr if f is not None] + [1])
    axes[1].set_ylim(0, max(5, top * 1.3))
    f1 = d.loc["ALL", "f1"] if "ALL" in d.index else None
    save(fig, "F4_detection.png", "B2, per host per 5 s window, pooled over repetitions. S6 has no attacker "
                                  "(recall n/a). Overall F1 = %s." % ("%.3f" % f1 if f1 is not None and pd.notna(f1) else "n/a"))


# --------------------------------------------------------------------------- F5/F6
def fig_perf():
    p = os.path.join(SUM, "perf.csv")
    if not os.path.exists(p):
        return
    d = pd.read_csv(p).set_index("mode")
    ms = [m for m in MODES if m in d.index]
    labels = [MODE_LABEL[m].replace(" ", "\n", 1) for m in ms]
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.2))
    bars(axes[0], labels, [d.loc[m, "first_rtt_ms_mean"] for m in ms], [MODE_C[m] for m in ms], "%.2f ms",
         [d.loc[m, "first_rtt_ms_std"] if pd.notna(d.loc[m, "first_rtt_ms_std"]) else 0 for m in ms])
    axes[0].set_title("First packet of a new flow (ms)", loc="left", fontsize=10)
    bars(axes[1], labels, [d.loc[m, "steady_rtt_ms_mean"] for m in ms], [MODE_C[m] for m in ms], "%.3f ms",
         [d.loc[m, "steady_rtt_ms_std"] if pd.notna(d.loc[m, "steady_rtt_ms_std"]) else 0 for m in ms])
    axes[1].set_title("Later packets, same flow (ms)", loc="left", fontsize=10)
    save(fig, "F5_latency.png", "Ping RTT u→web1. First packet includes ARP + controller decision + rule install; "
                                "later packets are switched in Open vSwitch.")
    fig, ax = plt.subplots(figsize=(5, 3.2))
    bars(ax, labels, [d.loc[m, "throughput_mbps_mean"] / 1000 for m in ms], [MODE_C[m] for m in ms], "%.1f",
         [d.loc[m, "throughput_mbps_std"] / 1000 if pd.notna(d.loc[m, "throughput_mbps_std"]) else 0 for m in ms])
    ax.set_title("Bulk transfer throughput (Gbit/s)", loc="left")
    save(fig, "F6_throughput.png", "iperf3 u2 → web1:8000, 10 s, mean ± std. Emulated links (no bandwidth cap).")


# --------------------------------------------------------------------------- F7/F10
def fig_controller(sid="S3"):
    d = run_dir("attacks", "B2", sid)
    if not d:
        return
    meta = json.load(open(os.path.join(d, "scenario.json")))
    p = pd.read_csv(os.path.join(d, "perf.csv"))
    p["t"] = p.ts - meta["attack_start"]
    fig, axes = plt.subplots(1, 3, figsize=(11, 3))
    for ax, col, title, c in ((axes[0], "packet_in_per_s", "Packet-ins per second", S1),
                              (axes[1], "cpu_pct", "Controller CPU (% of one core)", S2),
                              (axes[2], "flow_count", "Flow-table entries (all switches)", S3)):
        ax.axvspan(0, meta["attack_end"] - meta["attack_start"], color=INK2, alpha=0.08, lw=0)
        ax.plot(p.t, p[col], color=c, lw=2)
        ax.set_title(title, loc="left", fontsize=10)
        ax.set_xlabel("seconds since attack start")
        ax.set_ylim(bottom=0)
    save(fig, "F7_controller_load_%s.png" % sid, "AEGIS-ZT (B2) during %s, repetition 1. Shaded = attack period."
         % {"S3": "the SYN flood", "S1": "the port scan"}.get(sid, sid))


# --------------------------------------------------------------------------- F8
def fig_scale():
    p = os.path.join(SUM, "scale.csv")
    if not os.path.exists(p):
        return
    d = pd.read_csv(p).sort_values("hosts")
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.2))
    axes[0].plot(d.hosts, d.decision_us_median / 1000, color=S1, lw=2, marker="o", ms=6, label="median")
    axes[0].plot(d.hosts, d.decision_us_p95 / 1000, color=S2, lw=2, marker="o", ms=6, label="95th percentile")
    axes[0].set_title("Decision time per new flow (ms)", loc="left", fontsize=10)
    axes[0].legend()
    axes[1].plot(d.hosts, d.cpu_mean, color=S1, lw=2, marker="o", ms=6)
    axes[1].set_title("Controller CPU, mean (%)", loc="left", fontsize=10)
    for ax in axes:
        ax.set_xlabel("enrolled hosts")
        ax.set_ylim(bottom=0)
        ax.set_xticks(list(d.hosts))
    save(fig, "F8_scalability.png", "B2 with benign traffic from every host, 45 s, mean of repetitions.")


# --------------------------------------------------------------------------- F9
def fig_legit(by):
    sids = [s for s in ["S1", "S2", "S3", "S4", "S5", "S6"] if s in set(by.scenario)]
    if not sids:
        return
    fig, ax = plt.subplots(figsize=(8, 3.2))
    width = 0.26
    for i, m in enumerate(MODES):
        sub = by[by["mode"] == m].set_index("scenario")
        vals = [sub["legit_loss_pct"].get(s) if s in sub.index else None for s in sids]
        xs = [j + (i - 1) * width for j in range(len(sids))]
        r = ax.bar(xs, [0 if v is None or pd.isna(v) else v for v in vals], width=width, color=MODE_C[m],
                   label=MODE_LABEL[m], edgecolor=SURF, linewidth=2)
        for rect, v in zip(r, vals):
            if v is not None and pd.notna(v) and v > 0.5:
                ax.text(rect.get_x() + rect.get_width() / 2, rect.get_height() + 1, "%.0f" % v,
                        ha="center", fontsize=7.5, color=INK)
    ax.set_xticks(range(len(sids)))
    ax.set_xticklabels(sids)
    ax.set_ylabel("packet loss (%)")
    ax.set_title("Collateral damage: a legitimate user's packet loss during each attack", loc="left")
    ax.grid(axis="x", visible=False)
    ax.legend(loc="upper right")
    save(fig, "F9_legit_user_loss.png", "u2 pings web1 every 0.2 s during the attack. Mean of repetitions.")


def fig_retained(by):
    if "retains_access_pct" not in by.columns:
        return
    sids = [s for s in ["S1", "S2", "S3", "S4", "S5"] if s in set(by.scenario)]
    names = {"S1": "S1 scan", "S2": "S2 lateral", "S3": "S3 SYN flood", "S4": "S4 spoofing", "S5": "S5 slow scan"}
    fig, ax = plt.subplots(figsize=(8, 3.2))
    width = 0.26
    for i, m in enumerate(MODES):
        sub = by[by["mode"] == m].set_index("scenario")
        vals = [sub["retains_access_pct"].get(s) if s in sub.index else None for s in sids]
        xs = [j + (i - 1) * width for j in range(len(sids))]
        r = ax.bar(xs, [v if _ok(v) else 0 for v in vals], width=width, color=MODE_C[m], label=MODE_LABEL[m],
                   edgecolor=SURF, linewidth=2)
        for rect, v in zip(r, vals):
            ax.text(rect.get_x() + rect.get_width() / 2, rect.get_height() + 2,
                    "%.0f%%" % v if _ok(v) else "n/a", ha="center", fontsize=7.5, color=INK)
    ax.set_xticks(range(len(sids)))
    ax.set_xticklabels([names[s] for s in sids])
    ax.set_ylim(0, 135)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_ylabel("% of runs")
    ax.set_title("After the attack, does the compromised device keep its normal access?", loc="left")
    ax.grid(axis="x", visible=False)
    ax.legend(loc="upper center", ncol=3)
    save(fig, "F10_retained_access.png", "Checked right after the attack: attacker connects to its usual service "
                                         "(camera/sensor → collector:1883, laptop → web1:80). Lower is better.")


def main():
    os.makedirs(FIG, exist_ok=True)
    by_path = os.path.join(SUM, "by_scenario.csv")
    by = pd.read_csv(by_path) if os.path.exists(by_path) else pd.DataFrame()
    fig_trust_timeline()
    if not by.empty:
        fig_blast_radius(by)
        fig_containment(by)
        fig_legit(by)
        fig_retained(by)
    fig_detection()
    fig_perf()
    fig_controller("S3")
    fig_controller("S1")
    fig_scale()


if __name__ == "__main__":
    main()
