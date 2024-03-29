import json

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    set_ev_cls)
from ryu.lib.packet import ipv4, packet, tcp
from ryu.ofproto import ether, inet, ofproto_v1_3
from webob import Response

from utils import add_flow, mark_processed


redirect_tcp_instance_name = 'redirect_tcp_api_app'
url = '/redirecttcp'


class RedirectTCP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
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
            ipv4_dst='192.168.1.5',
            tcp_dst=80,
        )
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER),
        ]
        add_flow(datapath, 2, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if ip_pkt and ip_pkt.dst == '192.168.1.5' and tcp_pkt and tcp_pkt.dst_port == 80:
            self.logger.info('--> HTTP ip=%r port=%r, in_port=%r', ip_pkt.src, tcp_pkt.src_port, in_port)
            
            if self.redirects:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether.ETH_TYPE_IP,
                    ip_proto=inet.IPPROTO_TCP,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
                    tcp_src=tcp_pkt.src_port,
                    tcp_dst=tcp_pkt.dst_port,
                )
            
                actions = [
                    parser.OFPActionSetField(eth_dst='02:c7:bb:7d:3a:05'),
                    parser.OFPActionSetField(ipv4_dst='192.168.1.7'),
                    parser.OFPActionOutput(3),
                ]
            else:
                actions = [
                    parser.OFPActionOutput(1),
                ]

            if self.redirects:
                match_return = parser.OFPMatch(
                    in_port=3,
                    eth_type=ether.ETH_TYPE_IP,
                    ip_proto=inet.IPPROTO_TCP,
                    ipv4_src='192.168.1.7',
                    ipv4_dst=ip_pkt.src,
                    tcp_src=tcp_pkt.dst_port,
                    tcp_dst=tcp_pkt.src_port,
                )
                actions_return = [
                    parser.OFPActionSetField(eth_src='02:a2:45:be:83:6e'),
                    parser.OFPActionSetField(ipv4_src='192.168.1.5'),
                    parser.OFPActionOutput(in_port),
                ]
            else:
                match_return = parser.OFPMatch(
                    in_port=1,
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

            add_flow(datapath, 3, match, actions, idle_timeout=200)
            add_flow(datapath, 3, match_return, actions_return, idle_timeout=200)

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
