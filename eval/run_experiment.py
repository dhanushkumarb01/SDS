#!/usr/bin/env python3
"""Automated experiments for Phase 5 (SDS_Phase2_Design.md section 13).

Run from the project root as root (Mininet needs it):
  sudo python3 eval/run_experiment.py attacks --modes B0 B1 B2 --scenarios S1 S2 S3 S4 S5 S6 --reps 3
  sudo python3 eval/run_experiment.py perf    --modes B0 B1 B2 --reps 3
  sudo python3 eval/run_experiment.py scale   --extra 0 12 36

Each run gets a fresh controller + network and its own folder under results/raw/.
"""
import argparse
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "topology"))
sys.path.insert(0, os.path.join(ROOT, "attacks"))
from aegis_topo import build, prepare_hosts  # noqa: E402
from mininet.log import setLogLevel  # noqa: E402
from scenarios import RETAINED_ACCESS, SCENARIOS  # noqa: E402

VENV = os.path.expanduser("~%s/aegis-venv" % os.environ.get("SUDO_USER", ""))
RAW = os.path.join(ROOT, "results", "raw")
ROLE_OF = {"user": "user", "iot": "iot"}
WARMUP, ATTACK, COOLDOWN = 25, 40, 10


# --------------------------------------------------------------------------- helpers
def bash(script):
    """Wrap a bash script for Mininet's popen (which runs commands with sh -c)."""
    return "bash -c " + shlex.quote(script)


def sh(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def rest(path):
    with urllib.request.urlopen("http://127.0.0.1:8080" + path, timeout=3) as r:
        return json.load(r)


def start_controller(mode, run_dir, topology_file=None):
    sh("mn -c")                                    # also kills any old ryu-manager
    env = dict(os.environ, AEGIS_MODE=mode, AEGIS_LOG_DIR=run_dir)
    if topology_file:
        env["AEGIS_TOPOLOGY"] = topology_file
    log = open(os.path.join(run_dir, "ryu.log"), "w")
    p = subprocess.Popen([os.path.join(VENV, "bin", "ryu-manager"), "--ofp-tcp-listen-port", "6653",
                          "--wsapi-port", "8080", os.path.join(ROOT, "controller", "aegis_app.py")],
                         cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    for _ in range(40):
        try:
            if rest("/aegis/mode")["mode"] == mode:
                return p
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("controller did not start, see %s/ryu.log" % run_dir)


def stop_controller(p):
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        p.wait(timeout=10)
    except Exception:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except Exception:
            pass


def start_network(cfg):
    net = build(cfg)
    net.start()
    prepare_hosts(net, cfg)
    deadline = time.time() + 20
    while time.time() < deadline and rest("/aegis/stats")["switches"] < len(cfg["switches"]):
        time.sleep(0.5)
    time.sleep(1)
    return net


def start_benign(net, cfg, duration):
    py = shutil.which("python3")
    for name, h in cfg["hosts"].items():
        role = {"user": "user", "iot": "iot"}.get(h["zone"])
        if name == "web1":
            role = "web"
        if h["zone"] == "admin":
            role = "admin"
        if role:
            net.get(name).cmd("%s %s/traffic/benign.py --role %s --duration %d --seed %d > /dev/null 2>&1 &"
                              % (py, ROOT, role, duration, abs(hash(name)) % 1000))


def stop_net(net, cfg):
    for name in cfg["hosts"]:
        net.get(name).cmd("pkill -f benign.py; pkill -f services.py; pkill -f iperf3; pkill -f nmap; "
                          "pkill -f hping3; pkill -f arp_spoof.py; pkill -f lateral.sh")
    net.stop()


def load_cfg(path=None):
    with open(path or os.path.join(ROOT, "config", "topology.yaml")) as f:
        return yaml.safe_load(f)


def new_run_dir(kind, *parts):
    d = os.path.join(RAW, kind, "_".join(str(p) for p in parts))
    if os.path.exists(d):
        shutil.rmtree(d)
    os.makedirs(d)
    os.chmod(d, 0o777)
    return d


# --------------------------------------------------------------------------- attack runs
def run_attack(mode, sid, rep):
    sc = SCENARIOS[sid]
    run_dir = new_run_dir("attacks", mode, sid, "r%d" % rep)
    cfg = load_cfg()
    ctrl = start_controller(mode, run_dir)
    net = None
    try:
        net = start_network(cfg)
        total = WARMUP + ATTACK + COOLDOWN + 5
        start_benign(net, cfg, total)
        web1 = net.get("web1")
        web1.cmd("iperf3 -s -p 8000 -D")
        # spoof evidence on the victim side (S4): count packets that claim to be db1
        tcpdump = web1.popen("timeout %d tcpdump -nn -l -i web1-eth0 'src host 10.0.2.20 and tcp dst port 80' "
                             "> %s/spoof_delivered.txt 2>/dev/null" % (WARMUP + ATTACK + 5, run_dir), shell=True)
        time.sleep(WARMUP)

        # legitimate-user probe during the attack: u2 pings web1
        probe = net.get("u2").popen("ping -i 0.2 -w %d 10.0.2.10 > %s/legit_ping.txt 2>&1" % (ATTACK, run_dir),
                                    shell=True)
        avail = None
        if sid == "S3":   # collector availability for a real sensor during the flood
            avail = net.get("sen1").popen(bash(
                "end=$((SECONDS+%d)); ok=0; n=0; while [ $SECONDS -lt $end ]; do n=$((n+1)); "
                "nc -z -w1 10.0.2.30 1883 && ok=$((ok+1)); sleep 0.5; done; echo $ok $n > %s/availability.txt"
                % (ATTACK, run_dir)), shell=True)

        actor = sc["attacker"] or sc["actor"]
        cmd = sc["cmd"].format(dur=ATTACK, out=run_dir, root=ROOT, venv=VENV)
        t_start = time.time()
        att = net.get(actor).popen(bash(cmd), shell=True)
        att.wait()
        t_end = time.time()
        probe.wait()
        if avail:
            avail.wait()

        # post-attack: does the compromised device still have its normal access?
        retained = None
        if sc["attacker"] in RETAINED_ACCESS:
            ip, port = RETAINED_ACCESS[sc["attacker"]]
            out = net.get(sc["attacker"]).cmd("nc -z -w2 %s %d && echo OPEN || echo CLOSED" % (ip, port))
            retained = "OPEN" in out
        # post-attack: is the ARP cache of the users poisoned? (S4)
        poisoned = []
        if sid == "S4":
            sen1_mac = cfg["hosts"]["sen1"]["mac"]
            for u in ("u1", "u2", "u3"):
                if sen1_mac in net.get(u).cmd("ip neigh show 10.0.2.10"):
                    poisoned.append(u)
        time.sleep(COOLDOWN)
        tcpdump.terminate()
        meta = {"mode": mode, "scenario": sid, "rep": rep, "name": sc["name"],
                "attacker": sc["attacker"], "actor": actor, "attack_start": t_start, "attack_end": t_end,
                "window_s": 5, "warmup": WARMUP, "attack": ATTACK, "cooldown": COOLDOWN,
                "poisoned_victims": poisoned, "attacker_retains_access": retained,
                "stats_end": rest("/aegis/stats")}
        with open(os.path.join(run_dir, "scenario.json"), "w") as f:
            json.dump(meta, f, indent=2)
    finally:
        if net:
            stop_net(net, cfg)
        stop_controller(ctrl)
        sh("chmod -R a+rwX %s" % run_dir)
    print("  done %s %s r%d" % (mode, sid, rep), flush=True)


# --------------------------------------------------------------------------- performance runs
def run_perf(mode, rep):
    run_dir = new_run_dir("perf", mode, "r%d" % rep)
    cfg = load_cfg()
    ctrl = start_controller(mode, run_dir)
    net = None
    res = {"mode": mode, "rep": rep}
    try:
        net = start_network(cfg)
        web1 = net.get("web1")
        web1.cmd("iperf3 -s -p 8000 -D")
        time.sleep(2)
        # first-packet latency: brand-new flows (ARP + controller decision + rule install)
        firsts = []
        for u in ("u1", "u2", "u3"):
            out = net.get(u).cmd("ping -c1 -W3 10.0.2.10")
            firsts.append(_rtt(out))
        # steady-state latency on the established flow
        out = net.get("u1").cmd("ping -c 50 -i 0.1 10.0.2.10")
        res["first_rtt_ms"] = firsts
        res["steady_rtts_ms"] = _rtts(out)
        # throughput of an allowed bulk flow
        out = net.get("u2").cmd("iperf3 -c 10.0.2.10 -p 8000 -t 10 -J")
        try:
            j = json.loads(out[out.index("{"):])
            res["throughput_mbps"] = j["end"]["sum_received"]["bits_per_second"] / 1e6
            res["retransmits"] = j["end"]["sum_sent"].get("retransmits")
        except Exception:
            res["throughput_mbps"] = None
        res["stats_end"] = rest("/aegis/stats")
        with open(os.path.join(run_dir, "perf.json"), "w") as f:
            json.dump(res, f, indent=2)
    finally:
        if net:
            stop_net(net, cfg)
        stop_controller(ctrl)
        sh("chmod -R a+rwX %s" % run_dir)
    print("  done perf %s r%d: first %s ms, tput %s Mbit/s" % (mode, rep, res.get("first_rtt_ms"),
                                                            round(res.get("throughput_mbps") or 0)), flush=True)


def _rtts(out):
    vals = []
    for line in out.splitlines():
        if "time=" in line:
            vals.append(float(line.split("time=")[1].split()[0]))
    return vals


def _rtt(out):
    v = _rtts(out)
    return v[0] if v else None


# --------------------------------------------------------------------------- scalability runs
def scaled_topology(extra, path):
    cfg = load_cfg()
    for i in range(extra // 2):
        cfg["hosts"]["ux%d" % i] = {"zone": "user", "role": "laptop", "ip": "10.0.1.%d" % (100 + i),
                                    "mac": "00:00:00:00:a1:%02x" % i, "switch": "s1", "port": 20 + i, "services": []}
        cfg["hosts"]["ix%d" % i] = {"zone": "iot", "role": "sensor", "ip": "10.0.3.%d" % (100 + i),
                                    "mac": "00:00:00:00:a3:%02x" % i, "switch": "s3", "port": 20 + i, "services": []}
    with open(path, "w") as f:
        yaml.safe_dump(cfg, f)
    return cfg


def run_scale(extra, rep):
    run_dir = new_run_dir("scale", "h%d" % extra, "r%d" % rep)
    topo = os.path.join(run_dir, "topology.yaml")
    cfg = scaled_topology(extra, topo)
    ctrl = start_controller("B2", run_dir, topo)
    net = None
    try:
        net = start_network(cfg)
        start_benign(net, cfg, 45)
        time.sleep(45)
        res = {"extra_hosts": extra, "hosts": len(cfg["hosts"]), "rep": rep, "stats_end": rest("/aegis/stats")}
        with open(os.path.join(run_dir, "scale.json"), "w") as f:
            json.dump(res, f, indent=2)
    finally:
        if net:
            stop_net(net, cfg)
        stop_controller(ctrl)
        sh("chmod -R a+rwX %s" % run_dir)
    print("  done scale +%d r%d" % (extra, rep), flush=True)


# --------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["attacks", "perf", "scale"])
    ap.add_argument("--modes", nargs="+", default=["B0", "B1", "B2"])
    ap.add_argument("--scenarios", nargs="+", default=list(SCENARIOS))
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--extra", nargs="+", type=int, default=[0, 12, 36])
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run with sudo")
    setLogLevel("warning")
    sh("service openvswitch-switch start")
    os.makedirs(RAW, exist_ok=True)
    sh("chmod -R a+rwX %s" % os.path.join(ROOT, "results"))
    t0 = time.time()
    if a.kind == "attacks":
        for rep in range(1, a.reps + 1):
            for sid in a.scenarios:
                for mode in a.modes:
                    run_attack(mode, sid, rep)
    elif a.kind == "perf":
        for rep in range(1, a.reps + 1):
            for mode in a.modes:
                run_perf(mode, rep)
    else:
        for rep in range(1, a.reps + 1):
            for extra in a.extra:
                run_scale(extra, rep)
    sh("mn -c")
    print("finished in %.1f min" % ((time.time() - t0) / 60))


if __name__ == "__main__":
    main()
