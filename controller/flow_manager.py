"""OpenFlow 1.3 rule builders for the AEGIS-ZT pipeline.

Pipeline (SDS_Phase2_Design.md section 8):
  Table 0  ADMISSION     identity binding, ARP to controller
  Table 1  TIER GATE     quarantine profile
  Table 2  AUTHORIZATION allowed/denied flows with leases
  Table 3  FORWARDING    destination MAC -> output port

The module has no Ryu imports at load time (datapath objects carry the
ofproto/parser), so the cookie helpers can be unit-tested anywhere.
"""
T_ADMISSION, T_TIER, T_AUTH, T_FWD = 0, 1, 2, 3

# Cookie layout: | host_id (16) | type (8) | sequence (40) |
C_ADMIT, C_ALLOW, C_DENY, C_QUAR, C_FWD, C_REV, C_SYS = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F
# C_ALLOW = forward rule of an allowed flow (traffic the initiator sends)
# C_REV   = its reply rule (traffic the responder sends back); both carry the
#           initiator's host id, so counters can be attributed per direction.
HOST_TYPE_MASK = 0xFFFFFF0000000000
TYPE_MASK = 0x0000FF0000000000

PRIO_ALLOW, PRIO_DENY = 200, 100
IP_PROTO = {"icmp": 1, "tcp": 6, "udp": 17}


def cookie(host_id: int, ctype: int, seq: int = 0) -> int:
    return ((host_id & 0xFFFF) << 48) | ((ctype & 0xFF) << 40) | (seq & 0xFFFFFFFFFF)


def cookie_fields(c: int):
    """Decode a cookie into (host_id, type, seq)."""
    return (c >> 48) & 0xFFFF, (c >> 40) & 0xFF, c & 0xFFFFFFFFFF


class FlowManager:
    def __init__(self, logger):
        self.log = logger
        self._seq = 0

    def next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFFFFFFFF
        return self._seq

    # ---- primitives ----------------------------------------------------
    def add_flow(self, dp, table_id, priority, match, instructions,
                 idle=0, hard=0, cookie_=0, notify=False):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        flags = ofp.OFPFF_SEND_FLOW_REM if notify else 0
        dp.send_msg(parser.OFPFlowMod(datapath=dp, table_id=table_id, priority=priority,
                                      match=match, instructions=instructions,
                                      idle_timeout=idle, hard_timeout=hard,
                                      cookie=cookie_, flags=flags))

    @staticmethod
    def goto(dp, table_id):
        return [dp.ofproto_parser.OFPInstructionGotoTable(table_id)]

    @staticmethod
    def apply(dp, actions):
        return [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]

    def to_controller(self, dp):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        return self.apply(dp, [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])

    def delete_by_cookie(self, dp, cookie_value, mask=HOST_TYPE_MASK):
        """Bulk-delete rules whose cookie matches value under mask."""
        ofp, parser = dp.ofproto, dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                      table_id=ofp.OFPTT_ALL, out_port=ofp.OFPP_ANY,
                                      out_group=ofp.OFPG_ANY, cookie=cookie_value,
                                      cookie_mask=mask, match=parser.OFPMatch()))

    def clear_all(self, dp):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                      table_id=ofp.OFPTT_ALL, out_port=ofp.OFPP_ANY,
                                      out_group=ofp.OFPG_ANY, match=parser.OFPMatch()))

    def packet_out(self, dp, in_port, out_port, data):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port,
                                        actions=[parser.OFPActionOutput(out_port)], data=data))

    # ---- pipeline bootstrap --------------------------------------------
    def install_pipeline(self, dp, inventory, admission: bool, auth_miss_to_controller: bool):
        """Install the static skeleton of all four tables on a switch.

        admission=False gives the flat baseline (B0): no identity binding.
        auth_miss_to_controller=False lets admitted traffic skip authorization.
        """
        parser = dp.ofproto_parser
        sys_c = cookie(0, C_SYS)
        self.clear_all(dp)

        # Table 0: ARP -> controller; drop IPv6/LLDP noise; admit enrolled hosts;
        # traffic arriving on inter-switch ports was already checked at its edge.
        self.add_flow(dp, T_ADMISSION, 300, parser.OFPMatch(eth_type=0x0806), self.to_controller(dp), cookie_=sys_c)
        self.add_flow(dp, T_ADMISSION, 250, parser.OFPMatch(eth_type=0x86DD), [], cookie_=sys_c)
        self.add_flow(dp, T_ADMISSION, 250, parser.OFPMatch(eth_type=0x88CC), [], cookie_=sys_c)
        for p in inventory.uplink_ports(dp.id):
            self.add_flow(dp, T_ADMISSION, 150, parser.OFPMatch(in_port=p), self.goto(dp, T_FWD), cookie_=sys_c)
        if admission:
            for h in inventory.hosts_on(dp.id):
                m = parser.OFPMatch(in_port=h.port, eth_src=h.mac, eth_type=0x0800, ipv4_src=h.ip)
                self.add_flow(dp, T_ADMISSION, 200, m, self.goto(dp, T_TIER), cookie_=cookie(h.host_id, C_ADMIT))
            self.add_flow(dp, T_ADMISSION, 0, parser.OFPMatch(), self.to_controller(dp), cookie_=sys_c)
        else:
            self.add_flow(dp, T_ADMISSION, 100, parser.OFPMatch(eth_type=0x0800), self.goto(dp, T_TIER), cookie_=sys_c)
            self.add_flow(dp, T_ADMISSION, 0, parser.OFPMatch(), [], cookie_=sys_c)

        # Table 1: quarantine rules are added per host; default -> authorization.
        self.add_flow(dp, T_TIER, 0, parser.OFPMatch(), self.goto(dp, T_AUTH), cookie_=sys_c)

        # Table 2: a miss asks the controller (the Zero Trust decision point),
        # or skips straight to forwarding in open/flat modes.
        miss = self.to_controller(dp) if auth_miss_to_controller else self.goto(dp, T_FWD)
        self.add_flow(dp, T_AUTH, 0, parser.OFPMatch(), miss, cookie_=sys_c)

        # Table 3: proactive forwarding to every enrolled host; unknown -> drop.
        for h in inventory.hosts.values():
            port = inventory.out_port(dp.id, h)
            if port is None:
                continue
            self.add_flow(dp, T_FWD, 100, parser.OFPMatch(eth_dst=h.mac),
                          self.apply(dp, [parser.OFPActionOutput(port)]),
                          cookie_=cookie(h.host_id, C_FWD))
        self.add_flow(dp, T_FWD, 0, parser.OFPMatch(), [], cookie_=sys_c)

    # ---- authorization rules (Table 2) ---------------------------------
    @staticmethod
    def l4_match(parser, src_ip, dst_ip, proto, port, reverse=False):
        kw = {"eth_type": 0x0800, "ipv4_src": src_ip, "ipv4_dst": dst_ip, "ip_proto": IP_PROTO[proto]}
        if proto in ("tcp", "udp") and port is not None:
            kw["%s_%s" % (proto, "src" if reverse else "dst")] = port
        return parser.OFPMatch(**kw)

    def install_allow(self, src_dp, dst_dp, src, dst, proto, port, idle, hard):
        """Forward rule on the initiator's edge switch + reverse (reply) rule on
        the responder's edge switch. Both carry the initiator's host id, so a
        purge of the initiator removes both."""
        fwd = self.l4_match(src_dp.ofproto_parser, src.ip, dst.ip, proto, port)
        self.add_flow(src_dp, T_AUTH, PRIO_ALLOW, fwd, self.goto(src_dp, T_FWD), idle=idle, hard=hard,
                      cookie_=cookie(src.host_id, C_ALLOW, self.next_seq()), notify=True)
        rev = self.l4_match(dst_dp.ofproto_parser, dst.ip, src.ip, proto, port, reverse=True)
        self.add_flow(dst_dp, T_AUTH, PRIO_ALLOW, rev, self.goto(dst_dp, T_FWD), idle=idle, hard=hard,
                      cookie_=cookie(src.host_id, C_REV, self.next_seq()))

    def install_deny(self, dp, src, dst_ip, proto, port, idle, attribute=True):
        """Short-lived drop rule: stops repeated packet-ins, its counter feeds E1.
        attribute=False (host id 0) for silently dropped replies: nobody is penalised."""
        m = self.l4_match(dp.ofproto_parser, src.ip, dst_ip, proto, port)
        self.add_flow(dp, T_AUTH, PRIO_DENY, m, [], idle=idle,
                      cookie_=cookie(src.host_id if attribute else 0, C_DENY, self.next_seq()))

    def install_spoof_drop(self, dp, in_port, src_ip, host_id, idle=10):
        """Table 0 drop for a spoofed/unenrolled source, so it stops hitting the controller."""
        parser = dp.ofproto_parser
        m = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=src_ip)
        self.add_flow(dp, T_ADMISSION, 100, m, [], idle=idle, cookie_=cookie(host_id, C_DENY, self.next_seq()))

    # ---- tier enforcement (Table 1) ------------------------------------
    def install_quarantine(self, dp, host, rem_ip, rem_port):
        """Quarantined host may reach only the remediation service; all else dropped."""
        parser = dp.ofproto_parser
        c = cookie(host.host_id, C_QUAR, self.next_seq())
        allow = parser.OFPMatch(eth_src=host.mac, eth_type=0x0800, ipv4_dst=rem_ip, ip_proto=6, tcp_dst=rem_port)
        self.add_flow(dp, T_TIER, 200, allow, self.goto(dp, T_AUTH), cookie_=c)
        self.add_flow(dp, T_TIER, 190, parser.OFPMatch(eth_src=host.mac, eth_type=0x0800), [], cookie_=c)

    def purge_host(self, dps, host_id, types=(C_ALLOW, C_REV, C_DENY)):
        for dp in dps:
            for t in types:
                self.delete_by_cookie(dp, cookie(host_id, t), HOST_TYPE_MASK)

    def purge_type(self, dps, ctype):
        for dp in dps:
            self.delete_by_cookie(dp, cookie(0, ctype), TYPE_MASK)
