#!/usr/bin/env python3
"""Realistic background traffic, run inside a Mininet host (stdlib only).

  python3 traffic/benign.py --role user --duration 120
Roles (all flows are ALLOWED by policy.yaml, so a well-behaved network shows
no penalties):
  user   browse web1:80 every ~2 s, DNS lookup every ~5 s
  iot    publish to col1:1883 every ~3 s, DNS lookup every ~10 s
  web    query db1:3306 every ~3 s
  admin  ssh to web1:22 every ~10 s (maintenance window)
"""
import argparse
import random
import socket
import time

WEB, DB, COL, DNS = ("10.0.2.10", 80), ("10.0.2.20", 3306), ("10.0.2.30", 1883), ("10.0.2.53", 53)
SSH_WEB = ("10.0.2.10", 22)


def tcp(addr, payload=b"hello\r\n\r\n"):
    try:
        with socket.create_connection(addr, timeout=2) as s:
            s.sendall(payload)
            s.recv(256)
    except OSError:
        pass


def dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.sendto(b"query web1.corp", DNS)
        s.recvfrom(256)
    except OSError:
        pass
    finally:
        s.close()


PLANS = {
    "user":  [(2.0, lambda: tcp(WEB, b"GET / HTTP/1.0\r\n\r\n")), (5.0, dns)],
    "iot":   [(3.0, lambda: tcp(COL, b"telemetry temp=21.5\n")), (10.0, dns)],
    "web":   [(3.0, lambda: tcp(DB, b"SELECT 1;\n"))],
    "admin": [(10.0, lambda: tcp(SSH_WEB, b"SSH-2.0-admin\r\n"))],
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", required=True, choices=sorted(PLANS))
    ap.add_argument("--duration", type=float, default=3600)
    ap.add_argument("--seed", type=int, default=None)
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    end = time.time() + a.duration
    nxt = [time.time() + rnd.uniform(0, p) for p, _ in PLANS[a.role]]
    while time.time() < end:
        now = time.time()
        for i, (period, act) in enumerate(PLANS[a.role]):
            if now >= nxt[i]:
                act()
                nxt[i] = now + period * rnd.uniform(0.6, 1.4)
        time.sleep(0.1)


if __name__ == "__main__":
    main()
