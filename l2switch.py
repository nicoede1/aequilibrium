from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ethernet, packet
from ryu.ofproto import ofproto_v1_3

from utils import add_flow, has_processed


class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_tables = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if has_processed(ev):
            return

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id
        self.mac_tables.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src

        in_port = msg.match['in_port']
        self.mac_tables[dpid][src] = in_port

        out_port = self.mac_tables[dpid].get(dst, ofproto.OFPP_FLOOD)

        self.logger.info('packet in dpid=%r src=%r dst=%r in_port=%r', dpid, src, dst, in_port)

        actions = [parser.OFPActionOutput(
            out_port,
        )]

        if out_port is not ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst,
            )
            add_flow(datapath, 1, match, actions, idle_timeout=20)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)
