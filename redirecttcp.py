from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import ether_types, in_proto, ipv4, tcp


class PacketRedirector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PacketRedirector, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install a flow rule to redirect HTTP packets
        match = parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP,
                               nw_proto=in_proto.IPPROTO_TCP,
                               tp_dst=80,
                               eth_dst='02:90:90:fc:7b:5a',  # Destination MAC
                               ipv4_dst='10.10.1.2')  # Destination IP
        actions = [parser.OFPActionSetField(ipv4_dst='10.10.1.3'),
                   parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 100, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
