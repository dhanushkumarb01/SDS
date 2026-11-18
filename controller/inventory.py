"""Device identity registry (pure Python, no Ryu imports).

Loads config/topology.yaml and answers "who is this?" and "where is it?"
questions for the controller. Also computes, for every switch, which port
leads towards every host (used to build forwarding table 3).
"""
from typing import Dict, List, Optional, Set

import networkx as nx
import yaml

from models import Host, Switch


class Inventory:
    def __init__(self, path: str):
        with open(path) as f:
            cfg = yaml.safe_load(f)

        self.switches: Dict[str, Switch] = {
            name: Switch(name=name, dpid=int(s["dpid"]), role=s["role"], zone=s.get("zone"))
            for name, s in cfg["switches"].items()
        }
        self._by_dpid: Dict[int, Switch] = {s.dpid: s for s in self.switches.values()}

        self.hosts: Dict[str, Host] = {}
        for i, (name, h) in enumerate(cfg["hosts"].items(), start=1):
            self.hosts[name] = Host(name=name, zone=h["zone"], role=h["role"], ip=str(h["ip"]),
                                    mac=h["mac"].lower(), switch=h["switch"], port=int(h["port"]),
                                    host_id=i, services=tuple(h.get("services") or ()))
        self._by_id = {h.host_id: h for h in self.hosts.values()}
        self._by_ip = {h.ip: h for h in self.hosts.values()}
        self._by_mac = {h.mac: h for h in self.hosts.values()}
        self._by_loc = {(h.switch, h.port): h for h in self.hosts.values()}

        # Switch graph; each edge remembers the port on both ends.
        self.graph = nx.Graph()
        self.graph.add_nodes_from(self.switches)
        self._uplinks: Dict[str, Set[int]] = {s: set() for s in self.switches}
        for a, pa, b, pb in cfg["links"]:
            self.graph.add_edge(a, b, ports={a: int(pa), b: int(pb)})
            self._uplinks[a].add(int(pa))
            self._uplinks[b].add(int(pb))

    # ---- lookups -------------------------------------------------------
    def by_ip(self, ip: str) -> Optional[Host]:
        return self._by_ip.get(ip)

    def by_mac(self, mac: str) -> Optional[Host]:
        return self._by_mac.get(mac.lower())

    def by_name(self, name: str) -> Optional[Host]:
        return self.hosts.get(name)

    def by_id(self, host_id: int) -> Optional[Host]:
        return self._by_id.get(host_id)

    def switch_by_dpid(self, dpid: int) -> Optional[Switch]:
        return self._by_dpid.get(dpid)

    def at(self, dpid: int, port: int) -> Optional[Host]:
        """The enrolled host attached to (switch, port), if any."""
        sw = self.switch_by_dpid(dpid)
        return self._by_loc.get((sw.name, port)) if sw else None

    def hosts_on(self, dpid: int) -> List[Host]:
        sw = self.switch_by_dpid(dpid)
        return [h for h in self.hosts.values() if sw and h.switch == sw.name]

    def uplink_ports(self, dpid: int) -> Set[int]:
        sw = self.switch_by_dpid(dpid)
        return set(self._uplinks.get(sw.name, set())) if sw else set()

    # ---- identity check (Table 0 / spoofing) ---------------------------
    def binding_ok(self, dpid: int, port: int, mac: str, ip: Optional[str] = None) -> bool:
        """True if (switch, port, MAC[, IP]) matches an enrolled device."""
        h = self.at(dpid, port)
        if h is None or h.mac != mac.lower():
            return False
        return ip is None or h.ip == ip

    # ---- forwarding ----------------------------------------------------
    def out_port(self, dpid: int, host: Host) -> Optional[int]:
        """Port on switch `dpid` that leads towards `host`."""
        sw = self.switch_by_dpid(dpid)
        if sw is None:
            return None
        if host.switch == sw.name:
            return host.port
        try:
            path = nx.shortest_path(self.graph, sw.name, host.switch)
        except nx.NetworkXNoPath:
            return None
        return self.graph.edges[path[0], path[1]]["ports"][sw.name]
