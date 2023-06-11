#!/usr/bin/python3
import json
import requests
import fileinput
import time
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    set_ev_cls)
from ryu.lib.packet import ipv4, packet, tcp
from ryu.ofproto import ether, inet, ofproto_v1_3
from webob import Response

from utils import add_flow, mark_processed, server_status

redirect_tcp_instance_name = 'redirect_tcp_api_app'
url = '/redirecttcp'
cont = 0

throughput_1 = server_status('10.10.1.2')
throughput_2 = server_status('10.10.1.3')


class RedirectTCP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RedirectTCP, self).__init__(*args, **kwargs)
        self.redirects = True
        wsgi = kwargs['wsgi']
        wsgi.register(RedirectTCPController, {redirect_tcp_instance_name: self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=ether.ETH_TYPE_IP,
            ip_proto=inet.IPPROTO_TCP,
            ipv4_dst='10.10.1.3',
            tcp_dst=80,
        )
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER),
        ]
        add_flow(datapath, 2, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        global cont
        global throughput_1
        global throughput_2


        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        
       

        if throughput_1 >= throughput_2:
            server = '10.10.1.3'
            server_bad = '10.10.1.2'
            mac_bad = '02:2a:a0:91:63:5b'
            mac = '02:ed:17:29:c6:ed'
        elif throughput_1 < throughput_2:
            server = '10.10.1.2'
            server_bad = '10.10.1.3'
            mac_bad = '02:ed:17:29:c6:ed'
            mac = '02:2a:a0:91:63:5b'

        if ip_pkt and ip_pkt.dst == server_bad and tcp_pkt and tcp_pkt.dst_port == 80:
            self.logger.info('--> HTTP ip=%r port=%r', ip_pkt.src, tcp_pkt.src_port)

            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=ether.ETH_TYPE_IP,
                ip_proto=inet.IPPROTO_TCP,
                ipv4_src=ip_pkt.src,
                ipv4_dst=ip_pkt.dst,
                tcp_src=tcp_pkt.src_port,
                tcp_dst=tcp_pkt.dst_port,
            )
            if self.redirects:
                actions = [
                    parser.OFPActionSetField(eth_dst=mac),
                    parser.OFPActionSetField(ipv4_dst=server),
                    parser.OFPActionOutput(2),
                ]
            else:
                actions = [
                    parser.OFPActionOutput(3),
                ]

            if self.redirects:
                match_return = parser.OFPMatch(
                    in_port=2,
                    eth_type=ether.ETH_TYPE_IP,
                    ip_proto=inet.IPPROTO_TCP,
                    ipv4_src=server,
                    ipv4_dst=ip_pkt.src,
                    tcp_src=tcp_pkt.dst_port,
                    tcp_dst=tcp_pkt.src_port,
                )
                actions_return = [
                    parser.OFPActionSetField(eth_src=mac_bad),
                    parser.OFPActionSetField(ipv4_src=server_bad),
                    parser.OFPActionOutput(in_port),
                ]
            else:
                match_return = parser.OFPMatch(
                    in_port=3,
                    eth_type=ether.ETH_TYPE_IP,
                    ip_proto=inet.IPPROTO_TCP,
                    ipv4_src=ip_pkt.dst,
                    ipv4_dst=ip_pkt.src,
                    tcp_src=tcp_pkt.dst_port,
                    tcp_dst=tcp_pkt.src_port,
                )
                actions_return = [
                    parser.OFPActionOutput(in_port),
                ]
            
            add_flow(datapath, 3, match, actions, hard_timeout=15)
            add_flow(datapath, 3, match_return, actions_return, hard_timeout=15)

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data,
            )
            datapath.send_msg(out)
            mark_processed(ev, self.__class__.__name__)



class RedirectTCPController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.redirect_tcp_app = data[redirect_tcp_instance_name]

    @route('redirecttcp', url, methods=['GET'])
    def list_redirect(self, req, **kwargs):
        redirect_tcp = self.redirect_tcp_app
        body = json.dumps({
            'enable': redirect_tcp.redirects,
        })
        return Response(content_type='application/json', body=body, charset='utf-8')

    @route('redirecttcp-change', url + '/change', methods=['GET'])
    def put_redirect(self, req, **kwargs):
        redirect_tcp = self.redirect_tcp_app
        redirect_tcp.redirects = not redirect_tcp.redirects

        body = json.dumps({
            'enable': redirect_tcp.redirects,
        })
        return Response(content_type='application/json', body=body, charset='utf-8')
