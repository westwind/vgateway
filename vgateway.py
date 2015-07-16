from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp 


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.vgateway = '172.16.0.254'
        self.vgMac = ['ab:cd:ef:00:00:01']
        self.count=0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        protocol = eth.ethertype
        dpid = datapath.id
        #self.logger.info("packet in %s %s %s %s, %d", dpid, src, dst, in_port,protocol)
        
        if protocol == 0x0806:
            pkt_arp = pkt.get_protocols(arp.arp)[0]
            if pkt_arp.dst_ip == self.vgateway:
                print("Packet Out: arp reply")
                data = self.arp_reply(pkt_arp)
                self.packetout(datapath, in_port, data)
        if protocol == 0x0800:
            pkt_ipv4 = pkt.get_protocols(ipv4.ipv4)[0]
            if pkt_ipv4.dst == self.vgateway and pkt_ipv4.proto == 1:
                self.count=self.count+1
                pkt_icmp = pkt.get_protocols(icmp.icmp)[0]
                data = self.icmp_reply(pkt)
                self.packetout(datapath, in_port, data)
                print("ICMP reply")
                print(pkt)
        if self.count >5:
            print("grtuitous arp")
            data = self.gratuitous_arp()
            self.packetout(datapath, in_port, data)
            self.count=0

    def packetout(self, datapath, in_port, data):
        parser = datapath.ofproto_parser
        actions = []
        actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=data)
        datapath.send_msg(out)

    def gratuitous_arp(self):
        reply_packet = packet.Packet()
        reply_packet.add_protocol(ethernet.ethernet(
            ethertype = 0x0806,
            dst = 'ff:ff:ff:ff:ff:ff',
            src = self.vgMac[0]))
        reply_packet.add_protocol(arp.arp(
            opcode = arp.ARP_REQUEST,
            src_mac = "ef:cd:ab:00:00:02",
            src_ip = self.vgateway,
            dst_mac = 'ff:ff:ff:ff:ff:ff',
            dst_ip = self.vgateway))
        reply_packet.serialize()
        return reply_packet.data

    def arp_reply(self, arp_request):
        reply_packet = packet.Packet()
        reply_packet.add_protocol(ethernet.ethernet(
            ethertype = 0x0806,
            dst = arp_request.src_mac,
            src = self.vgMac[0]))
        reply_packet.add_protocol(arp.arp(
            opcode = arp.ARP_REPLY,
            src_mac = self.vgMac[0],
            src_ip = self.vgateway,
            dst_mac = arp_request.src_mac,
            dst_ip = arp_request.src_ip))
        reply_packet.serialize()
        return reply_packet.data

    def icmp_reply(self, pkt):
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ipv4 = pkt.get_protocols(ipv4.ipv4)[0]
        pkt_icmp = pkt.get_protocols(icmp.icmp)[0]
        reply_packet = packet.Packet()
        reply_packet.add_protocol(ethernet.ethernet(
            ethertype = 0x0800,
            dst = pkt_eth.src,
            src = pkt_eth.dst))
        reply_packet.add_protocol(ipv4.ipv4(
            dst=pkt_ipv4.src,
            src=self.vgateway,
            proto=1))
        reply_packet.add_protocol(icmp.icmp(
            type_=0,
            data=pkt_icmp.data))
        reply_packet.serialize()
        return reply_packet.data
