import requests
import fileinput
import http.client as httplib
import datetime
# import schedule
import build_tcp as btcp  # not sure if it's the most correct
import time
from timeit import default_timer as timer
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types, ethernet, ipv4, packet, tcp, arp
from ryu.ofproto import ether, ofproto_v1_3, inet
from utils import server_status, mark_processed

# variables initiation
redirect_flag = 0  # This variable will be the trigger to redirect or not
# This variable will hold wheter there is the need to redirect or not
need_to_redirect_flag = 0
tempo = 0
throughput_1 = server_status('172.17.221.4')
throughput_2 = server_status('172.17.221.3')
start = timer()  # Timer usage to execute certain functions withouth the use of threads


class StreamRedirect(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StreamRedirect, self).__init__(*args, **kwargs)
        self.redirects = True
        self.mac_to_port = {}
        self.origin2 = ['02:d5:42:66:d1:b2', '10.10.1.2', '1']  # ether, ip , port sdn
        self.origin1 = ['02:e7:a7:0c:51:a3', '10.10.1.3', '2']

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # If there's a connection request to the origin1 then it will be sent to the controller
        match = parser.OFPMatch(
            eth_type=ether.ETH_TYPE_IP,
            ip_proto=inet.IPPROTO_TCP,
            ipv4_dst='10.10.1.3',
            tcp_dst=80,
        )
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER),
        ]
        self.add_flow(datapath, 5, match, actions)

        match = parser.OFPMatch(
            eth_type=ether.ETH_TYPE_IP,
            ip_proto=inet.IPPROTO_TCP,
            ipv4_dst='10.10.1.2',
            tcp_dst=80,
        )
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER),
        ]
        self.add_flow(datapath, 5, match, actions)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        global redirect_flag
        global need_to_redirect_flag
        global throughput_1
        global throughput_2
        global start
        global tempo

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        dst = pkt_eth.dst
        src = pkt_eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        if redirect_flag == 0:
            # First time connection verification
[B            if throughput_1 > throughput_2:
                server = '10.10.1.2'
                server_bad = '10.10.1.3'
                port_bad = self.origin1[2]
                mac = '02:d5:42:66:d1:b2'
                mac_bad = '02:e7:a7:0c:51:a3'
                port = self.origin2[2]
            else:
                server = '10.10.1.3'
                port = self.origin1[2]
                server_bad = '10.10.1.2'
                mac = '02:e7:a7:0c:51:a3'
                port_bad = self.origin1[2]
                mac_bad = '02:d5:42:66:d1:b2'

            if pkt_ip and pkt_ip.dst == server_bad and pkt_tcp and pkt_tcp.dst_port == 80:

                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether.ETH_TYPE_IP,
                    ip_proto=inet.IPPROTO_TCP,
                    ipv4_src=pkt_ip.src,
                    ipv4_dst=pkt_ip.dst,
                    tcp_src=pkt_tcp.src_port,
                    tcp_dst=pkt_tcp.dst_port,
                )
                if self.redirects:
                    actions = [
                        parser.OFPActionSetField(eth_dst=mac),
                        parser.OFPActionSetField(ipv4_dst=server),
                        parser.OFPActionOutput(2),
                    ]

                if self.redirects:
                    match_return = parser.OFPMatch(
                        in_port=2,
                        eth_type=ether.ETH_TYPE_IP,
                        ip_proto=inet.IPPROTO_TCP,
                        ipv4_src=server,
                        ipv4_dst=pkt_ip.src,
                        tcp_src=pkt_tcp.dst_port,
                        tcp_dst=pkt_tcp.src_port,
                    )
                    actions_return = [
                        parser.OFPActionSetField(eth_src=mac_bad),
                        parser.OFPActionSetField(ipv4_src=server_bad),
                        parser.OFPActionOutput(in_port),
                    ]

                self.add_flow(datapath, 2, match, actions, idle_timeout=10)
                self.add_flow(datapath, 3, match_return,
                              actions_return, idle_timeout=10)

                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data,
                )
                datapath.send_msg(out)
                # To avoid the switch overload, the first time it gets in here, it will be marked
                mark_processed(ev, self.__class__.__name__)

        end = timer()
        tempo = int(abs(start - end))

        if pkt_eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        # Every 60+ seconds there will be a new status recovery
        if (tempo >= 60):
            need_to_redirect_flag = 1
            start = timer()

            throughput_1 = server_status('172.17.221.4')
            throughput_2 = server_status('172.17.221.3')

        if pkt_ip:
            if need_to_redirect_flag == 1:
                # If throughput1 is higher but the destination is the same server do not redirect
                if (throughput_1 > throughput_2) and pkt_ip.dst == '10.10.1.2':
                    trash = 0
                else:
                    redirect_flag = redirect_flag + 1  # Redirect otherwise

                if (throughput_2 > throughput_1) and pkt_ip.dst == '10.10.1.3':
                    trash = 0
                else:
                    redirect_flag = redirect_flag + 1

            if redirect_flag > 1 and (pkt_ip.dst == '10.10.1.2' or pkt_ip.dst == '10.10.1.3'):
                self.logger.info('The redirect process has started')
                self._del_tcp_flow(datapath, ofproto, parser,
                                   in_port, pkt_eth, pkt_ip, pkt_tcp)
                btcp.finish_connection(ev)
                self._hot_swap(ev)
                self.logger.info('The redirect process is finished')
                redirect_flag = redirect_flag + 1

        if in_port != 1:
            self.logger.info("Packet in %s %s %s %s | %s **** %s ****",
                             dpid, src, dst, in_port, datetime.datetime.now(), tempo)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

  [B      if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
				datapath.send_msg(out)
        if redirect_flag == 0:
            redirect_flag = redirect_flag + 1

    def _hot_swap(self, ev):
        global redirect_flag
        global tempo
        msg = ev.msg  # Object representing a packet_in data structure.
        datapath = msg.datapath  # Switch Datapath ID
        ofproto = datapath.ofproto  # A module which exports OpenFlow definitions
        # A module which exports OpenFlow wire message encoder and decoder for the negotiated OpenFlow version.
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']  # get in_port of the packet to analyze

        pkt = packet.Packet(msg.data)
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        pkt_arp = pkt.get_protocol(arp.arp)
        dst = pkt_eth.dst
        src = pkt_eth.src
        dpid = datapath.id

        if ip_pkt and tcp_pkt and tcp_pkt.dst_port == 80:
            self.logger.info('--> HTTP ip=%r port=%r',
                             ip_pkt.src, tcp_pkt.src_port)
            if ip_pkt.dst == '10.10.1.2':
                original_ipv = self.origin2[1]
                original_ether = self.origin2[0]
                original_port = self.origin2[2]
                redirect_ipv = self.origin1[1]
                redirect_ether = self.origin1[0]
                redirect_port = self.origin1[2]
            if ip_pkt.dst == '10.10.1.3':
                original_ipv = self.origin1[1]
                original_ether = self.origin1[0]
                original_port = self.origin1[2]
                redirect_ipv = self.origin2[1]
                redirect_ether = self.origin2[0]
                redirect_port = self.origin2[2]

            # add flow: client -> origin
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=ether.ETH_TYPE_IP,
                                    ip_proto=inet.IPPROTO_TCP, tcp_dst=80)

            new_port = int(redirect_port)
            actions = []
            actions.append(parser.OFPActionSetField(ipv4_dst=redirect_ipv))
            actions.append(parser.OFPActionSetField(eth_dst=redirect_ether))
            actions.append(parser.OFPActionOutput(new_port))
            self.add_flow(datapath, 2000, match, actions)

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)

            # add flow: origin -> client
            match_r = parser.OFPMatch(in_port=new_port, eth_dst=src, eth_src=redirect_ether,
                                      eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, tcp_src=80)
            actions_r = []
            actions_r.append(parser.OFPActionSetField(ipv4_src=original_ipv))
            actions_r.append(parser.OFPActionSetField(eth_src=original_ether))
            actions_r.append(parser.OFPActionOutput(in_port))  # client port

            self.add_flow(datapath, 2000, match_r, actions_r)

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions_r, data=msg.data)
            datapath.send_msg(out)
            self.logger.info(
                'New flows were installed, from %s to %s', original_ipv, redirect_ipv)
            redirect_flag = 0
            tempo = 0

    def _del_tcp_flow(self, datapath, ofproto, parser, in_port, pkt_eth, pkt_ip, pkt_tcp):
        src = pkt_eth.src
        dst = pkt_eth.dst
        dpid = datapath.id

        if pkt_ip.dst == '10.10.1.2':
            server_bad = self.origin2[1]
            mac_bad = self.origin2[0]
            port_bad = int(self.origin2[2])
        else:
            server_bad = self.origin1[1]
            mac_bad = self.origin1[0]
            port_bad = int(self.origin1[2])

        # remove: origin - client flow
        match = parser.OFPMatch(
            eth_dst=src, in_port=port_bad, eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, tcp_src=80)
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

        # remove: client - origin flow
        match = parser.OFPMatch(
            eth_src=src, in_port=3, eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, tcp_dst=80)
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)
        self.logger.info('The old flows were deleted')
