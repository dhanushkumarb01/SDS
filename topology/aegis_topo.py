#!/usr/bin/env python3
"""AEGIS-ZT Mininet topology, built from config/topology.yaml.

Usage (from the project root):
  sudo python3 topology/aegis_topo.py            # start + interactive Mininet CLI
  sudo python3 topology/aegis_topo.py --test     # start, run connectivity checks, stop
  sudo python3 topology/aegis_topo.py --tc       # add bandwidth/delay limits (TCLink)

The Ryu controller must already be running on 127.0.0.1:6653.
"""
import argparse
import os
import sys
import time

import yaml
from mininet.cli import CLI
from mininet.link import Link, TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "config", "topology.yaml")
SERVICES = os.path.join(ROOT, "topology", "services.py")


def build(cfg, use_tc=False, ctrl_ip="127.0.0.1", ctrl_port=6653):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink if use_tc else Link,
                  autoSetMacs=False, build=False)
    net.addController("c0", controller=RemoteController, ip=ctrl_ip, port=ctrl_port)

    for name, s in cfg["switches"].items():
        net.addSwitch(name, dpid="%016x" % int(s["dpid"]), protocols="OpenFlow13",
                      failMode="secure")

    for a, pa, b, pb in cfg["links"]:
        opts = {"bw": 1000, "delay": "1ms"} if use_tc else {}
        net.addLink(a, b, port1=int(pa), port2=int(pb), **opts)

    for name, h in cfg["hosts"].items():
        host = net.addHost(name, ip="%s/16" % h["ip"], mac=h["mac"])
        opts = {"bw": 100, "delay": "1ms"} if use_tc else {}
        net.addLink(host, h["switch"], port2=int(h["port"]), **opts)

    net.build()
    return net


def prepare_hosts(net, cfg):
    py = sys.executable
    for name, h in cfg["hosts"].items():
        host = net.get(name)
        # IPv6 off: keeps the controller log free of neighbour-discovery noise.
        host.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1")
        svcs = h.get("services") or []
        if svcs:
            host.cmd("%s %s --name %s %s > /dev/null 2>&1 &" % (py, SERVICES, name, " ".join(svcs)))


def connectivity_test(net):
    """Quick bring-up check for mode 'open' (everything enrolled should reach everything)."""
    checks = [
        ("u1", "ping -c1 -W2 10.0.2.10", "u1 -> web1 ping"),
        ("cam1", "ping -c1 -W2 10.0.2.30", "cam1 -> col1 ping"),
        ("adm1", "ping -c1 -W2 10.0.9.10", "adm1 -> rem1 ping"),
        ("u1", "curl -s -m 3 http://10.0.2.10/", "u1 -> web1 HTTP"),
        ("web1", "nc -z -w2 10.0.2.20 3306 && echo OPEN", "web1 -> db1 tcp/3306"),
        ("cam1", "nc -z -w2 10.0.2.30 1883 && echo OPEN", "cam1 -> col1 tcp/1883"),
    ]
    ok = 0
    for host, cmd, label in checks:
        out = net.get(host).cmd(cmd)
        passed = (" 0% packet loss" in out) or ("hello" in out) or ("OPEN" in out)
        ok += passed
        print("[%s] %s" % ("PASS" if passed else "FAIL", label))
    # Negative check: u1 pretends to be db1 (spoofed source IP). Table 0 must drop it.
    u1 = net.get("u1")
    u1.cmd("ip addr add 10.0.2.20/16 dev u1-eth0")
    out = u1.cmd("ping -c1 -W2 -I 10.0.2.20 10.0.2.10")
    u1.cmd("ip addr del 10.0.2.20/16 dev u1-eth0")
    blocked = " 0% packet loss" not in out
    ok += blocked
    print("[%s] spoofed source IP (u1 as db1) is blocked" % ("PASS" if blocked else "FAIL"))
    total = len(checks) + 1
    print("--- %d/%d checks passed" % (ok, total))
    return ok == total


def _ok(out):
    return (" 0% packet loss" in out) or ("hello" in out) or ("OPEN" in out) or ("ECHO_OK" in out)


def acceptance_test(net):
    """Design section 14.2: the micro-segmentation matrix, run in modes B1/B2."""
    tcp = lambda ip, port: "nc -z -w2 %s %d && echo OPEN || echo CLOSED" % (ip, port)
    checks = [
        ("T1", "u1", "curl -s -m 3 http://10.0.2.10/", True, "user -> web1 HTTP"),
        ("T2", "u1", "ping -c2 -W2 10.0.2.10", True, "user -> web1 ping"),
        ("T3", "u1", "ping -c2 -W2 10.0.1.12", False, "user -> user (no laptop-to-laptop)"),
        ("T4", "u1", tcp("10.0.2.20", 3306), False, "user -> db1:3306"),
        ("T5", "web1", tcp("10.0.2.20", 3306), True, "web1 -> db1:3306 (app tier)"),
        ("T6", "cam1", tcp("10.0.2.30", 1883), True, "camera -> collector MQTT"),
        ("T7", "cam1", tcp("10.0.3.22", 22), False, "camera -> camera (no IoT-to-IoT)"),
        ("T8", "adm1", tcp("10.0.2.10", 22), True, "admin -> web1 ssh (window)"),
        ("T9", "u2", tcp("10.0.9.10", 8080), True, "user -> remediation"),
        ("T11", "u1", "echo hi | nc -u -w2 10.0.2.53 53 | grep -q hi && echo ECHO_OK", True, "user -> DNS (UDP reply)"),
        ("T12", "u1", tcp("10.0.2.10", 22), False, "user -> web1:22 (only port 80 allowed)"),
        ("T13", "cam1", "ping -c2 -W2 10.0.2.30", False, "camera ping collector (no ICMP rule)"),
    ]
    ok = 0
    for tid, host, cmd, expect, label in checks:
        got = _ok(net.get(host).cmd(cmd))
        passed = got == expect
        ok += passed
        print("[%s] %-4s %-42s expected %-5s got %s" % ("PASS" if passed else "FAIL", tid, label,
                                                       "ALLOW" if expect else "DENY", "ALLOW" if got else "DENY"))

    # T10: rogue (unenrolled) device plugged into the user switch at runtime
    s1 = net.get("s1")
    rogue = net.addHost("h99", ip="10.0.1.99/16", mac="00:00:00:00:01:99")
    link = net.addLink(rogue, s1, port2=9)
    s1.attach(link.intf2)
    rogue.configDefault(ip="10.0.1.99/16", mac="00:00:00:00:01:99")
    got = _ok(rogue.cmd("ping -c2 -W2 10.0.2.10"))
    ok += not got
    print("[%s] T10  %-42s expected DENY  got %s" % ("PASS" if not got else "FAIL",
                                                     "rogue unenrolled device -> web1", "ALLOW" if got else "DENY"))

    # T14: spoofed source IP
    u1 = net.get("u1")
    u1.cmd("ip addr add 10.0.2.20/16 dev u1-eth0")
    got = _ok(u1.cmd("ping -c1 -W2 -I 10.0.2.20 10.0.2.10"))
    u1.cmd("ip addr del 10.0.2.20/16 dev u1-eth0")
    ok += not got
    print("[%s] T14  %-42s expected DENY  got %s" % ("PASS" if not got else "FAIL",
                                                     "spoofed source IP (u1 as db1)", "ALLOW" if got else "DENY"))
    total = len(checks) + 2
    print("--- %d/%d acceptance checks passed" % (ok, total))
    return ok == total


def _rest(path, ip="127.0.0.1"):
    import json
    import urllib.request
    with urllib.request.urlopen("http://%s:8080%s" % (ip, path), timeout=3) as r:
        return json.load(r)


def scan_check(net, ip="127.0.0.1"):
    """B2: a 'hacked' camera (cam2, untouched by the acceptance tests) scans the
    network; AEGIS-ZT must contain it on its own while a bystander (u3) is unaffected."""
    tier = lambda: {h["name"]: (h["tier"], h["score"]) for h in _rest("/aegis/hosts", ip)}["cam2"]
    cam = net.get("cam2")
    print("*** cam2 before attack: %s (score %s)" % tier())
    print("[%s] cam2 can reach collector before attack" %
          ("PASS" if _ok(cam.cmd("nc -z -w2 10.0.2.30 1883 && echo OPEN")) else "FAIL"))
    t0 = time.time()
    scan = cam.popen("nmap -sS -T4 -n -Pn --max-retries 1 -p 1-1000 "
                     "10.0.1.11-13 10.0.2.10 10.0.2.20 10.0.2.30 10.0.2.53 10.0.3.21 10.0.3.23 10.0.4.10 "
                     "-oG /tmp/aegis_scan_check.gnmap", shell=True)
    seen, contained_at = None, None
    while time.time() - t0 < 40:
        t, s = tier()
        if t != seen:
            print("*** t=%5.1fs  cam2 -> %-11s score %s" % (time.time() - t0, t, s))
            seen = t
        if t == "QUARANTINED":
            contained_at = time.time() - t0
            break
        time.sleep(0.5)
    scan.terminate()
    time.sleep(1)
    reach_col = _ok(cam.cmd("nc -z -w2 10.0.2.30 1883 && echo OPEN"))
    reach_rem = _ok(cam.cmd("nc -z -w2 10.0.9.10 8080 && echo OPEN"))
    others = _ok(net.get("u3").cmd("curl -s -m 3 http://10.0.2.10/"))
    print("*** time-to-contain: %s" % ("%.1f s" % contained_at if contained_at else "NOT CONTAINED"))
    print("[%s] quarantined cam2 blocked from collector" % ("PASS" if not reach_col else "FAIL"))
    print("[%s] quarantined cam2 can still reach remediation" % ("PASS" if reach_rem else "FAIL"))
    print("[%s] bystander unaffected (u3 -> web1)" % ("PASS" if others else "FAIL"))
    return bool(contained_at) and not reach_col and reach_rem and others


def controller_mode(ip="127.0.0.1"):
    import json
    import urllib.request
    try:
        with urllib.request.urlopen("http://%s:8080/aegis/mode" % ip, timeout=3) as r:
            return json.load(r)["mode"]
    except Exception:
        return "open"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", action="store_true", help="run checks and exit")
    ap.add_argument("--tc", action="store_true", help="use TCLink bandwidth/delay limits")
    ap.add_argument("--hold", type=int, default=0, help="keep the network up N seconds without CLI")
    ap.add_argument("--controller", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=6653)
    a = ap.parse_args()

    setLogLevel("info")
    with open(CONFIG) as f:
        cfg = yaml.safe_load(f)
    net = build(cfg, use_tc=a.tc, ctrl_ip=a.controller, ctrl_port=a.port)
    net.start()
    prepare_hosts(net, cfg)
    info("*** Waiting for switches to connect and pipelines to install\n")
    time.sleep(3)
    try:
        if a.test:
            mode = controller_mode(a.controller)
            print("*** controller mode: %s" % mode)
            ok = acceptance_test(net) if mode in ("B1", "B2") else connectivity_test(net)
            if mode == "B2":
                ok = scan_check(net, a.controller) and ok
            sys.exit(0 if ok else 1)
        if a.hold:
            time.sleep(a.hold)
            return
        CLI(net)
    finally:
        for name in cfg["hosts"]:
            net.get(name).cmd("pkill -f 'services.py --name %s' 2>/dev/null" % name)
        net.stop()


if __name__ == "__main__":
    main()
