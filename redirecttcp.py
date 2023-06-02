from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

class PacketRedirector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PacketRedirector, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, MAIN_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Match packets from host 10.10.1.1 and TCP port 80
        match = parser.OFPMatch(
            eth_type=0x0800,  # IPv4
            ipv4_src='10.10.1.1',
            ip_proto=6,  # TCP
            tcp_dst=80
        )

        # Set the new destination MAC address to redirect packets to 10.10.1.3
        actions = [parser.OFPActionSetField(eth_dst='02:79:15:ab:5d:fc')]

        # Apply the actions to the matched packets
        instructions = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Add the flow entry to the switch's flow table
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,  # Set an appropriate priority
            match=match,
            instructions=instructions
        )
        datapath.send_msg(mod)
