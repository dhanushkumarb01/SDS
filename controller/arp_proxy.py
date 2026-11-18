"""Proxy ARP for AEGIS-ZT (Ryu-dependent).

The controller answers every ARP request itself, and only for destinations
the policy allows ("network invisibility", design section 8.5). ARP is never
flooded through the network.
"""
from ryu.lib.packet import arp, ethernet, ether_types, packet


class ArpProxy:
    def __init__(self, inventory, is_reachable, on_spoof, on_hidden, logger):
        """
        is_reachable(src_host, dst_host) -> bool : may src even learn dst exists?
        on_spoof(host_or_none, evidence)           : forged ARP from a device
        on_hidden(src_host, dst_ip)                : ARP for a forbidden/unknown target
        """
        self.inv = inventory
        self.is_reachable = is_reachable
        self.on_spoof = on_spoof
        self.on_hidden = on_hidden
        self.log = logger

    def handle(self, dp, in_port, pkt):
        eth = pkt.get_protocol(ethernet.ethernet)
        req = pkt.get_protocol(arp.arp)
        if req is None:
            return

        # Identity check: the ARP sender must be the device enrolled on this port.
        src = self.inv.at(dp.id, in_port)
        if src is None:
            if self.inv.switch_by_dpid(dp.id) and in_port in self.inv.uplink_ports(dp.id):
                return  # ARP never crosses switches in our design; ignore
            self.on_spoof(None, {"dpid": dp.id, "port": in_port, "arp_src_ip": req.src_ip,
                                 "reason": "UNENROLLED_PORT"})
            return
        if req.src_mac.lower() != src.mac or req.src_ip != src.ip:
            self.on_spoof(src, {"claimed_ip": req.src_ip, "claimed_mac": req.src_mac,
                                "reason": "ARP_BINDING_MISMATCH"})
            return

        if req.opcode != arp.ARP_REQUEST:
            return  # hosts never need to send replies: the controller answers for everyone

        dst = self.inv.by_ip(req.dst_ip)
        if dst is None or not self.is_reachable(src, dst):
            self.on_hidden(src, req.dst_ip)
            return  # silence: for src, dst does not exist

        self._reply(dp, in_port, eth, req, dst.mac)

    def _reply(self, dp, in_port, req_eth, req_arp, target_mac):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                         dst=req_eth.src, src=target_mac))
        p.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=target_mac, src_ip=req_arp.dst_ip,
                               dst_mac=req_arp.src_mac, dst_ip=req_arp.src_ip))
        p.serialize()
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=ofp.OFPP_CONTROLLER,
                                        actions=[parser.OFPActionOutput(in_port)], data=p.data))
