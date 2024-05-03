import time
from ryu.lib.packet.tcp import *
from ryu.ofproto import ether
from ryu.lib.packet import ethernet, ipv4, tcp, packet
from ryu.lib.packet import in_proto as inet

def finish_connection(ev):
    msg = ev.msg
    datapath = msg.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    in_port = msg.match['in_port']

    pkt = packet.Packet(msg.data)
    pkt_eth = pkt.get_protocol(ethernet.ethernet)
    pkt_ip = pkt.get_protocol(ipv4.ipv4)
    pkt_tcp = pkt.get_protocol(tcp.tcp)

    if pkt_ip.dst == '192.168.1.14':
        origin_lst = ['02:28:fc:fd:ee:1b', '192.168.1.3', 3]
    else:
        origin_lst = ['02:54:2d:77:5d:2d', '192.168.1.14', 7]
        
    print('pkt_tcp: ', pkt_tcp)

    #identify the seq and ack number
	n_seq = pkt_tcp.seq
    n_ack = pkt_tcp.ack
    n_offset = pkt_tcp.offset
    n_window_size = pkt_tcp.window_size
    n_option = pkt_tcp.option

    # 0 ether, 1 ip , 2 port sw sdn
    ether_dst = origin_lst[0]
    ipv4_dst = origin_lst[1]
    out_port = int(origin_lst[2])

    e = ethernet.ethernet(dst=ether_dst,
                          src=pkt_eth.src,
                          ethertype=ether.ETH_TYPE_IP)

    i = ipv4.ipv4(version=4, header_length=5, tos=0,
                  total_length=0, identification=0, flags=2,  
                  offset=0, ttl=64, proto=inet.IPPROTO_TCP, csum=0,
                  src=pkt_ip.src,
                  dst=ipv4_dst)

    # bits=17 -> FIN + ACK
    t = tcp.tcp(src_port=pkt_tcp.src_port, dst_port=pkt_tcp.dst_port, seq=n_seq, ack=n_ack,
                offset=n_offset, bits=17, window_size=n_window_size, csum=0, urgent=2,
                option=n_option)  # urgent = 2, tag to check the crafted packet on wireshark

    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(i)
    p.add_protocol(t)
    p.serialize()  # forces automatic checksum calculations
    d = p.data  

    actions = [parser.OFPActionOutput(out_port)]

    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                              in_port=in_port, actions=actions, data=d)
    datapath.send_msg(out)

    # wait for origin to send the FIN+ACK
    time.sleep(0.5)

    print("TCP FIN+ACK sent to % s " % pkt_ip.dst)
    #  bits=16 -> ACK
    t = tcp.tcp(src_port=pkt_tcp.src_port, dst_port=pkt_tcp.dst_port, seq=n_seq+1, ack=n_ack+1,
                 offset=n_offset, bits=16, window_size=n_window_size, csum=0,
                 urgent=3, option=n_option)  # urgent = 3, tag to check the crafted packet on wireshark

    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(i)
    p.add_protocol(t)
    p.serialize()
    d = p.data
    actions = [parser.OFPActionOutput(out_port)]

    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                              in_port=in_port, actions=actions, data=d)
    datapath.send_msg(out)
    print("TCP ACK sent to % s " % pkt_ip.dst)
