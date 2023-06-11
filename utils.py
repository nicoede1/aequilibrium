#!/usr/bin/python3
import requests
import fileinput
import httplib


def add_flow(datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    inst = [parser.OFPInstructionActions(
        ofproto.OFPIT_APPLY_ACTIONS,
        actions,
    )]
    mod = parser.OFPFlowMod(
        datapath=datapath,
        priority=priority,
        match=match,
        instructions=inst,
        idle_timeout=idle_timeout,
        hard_timeout=hard_timeout,
    )
    datapath.send_msg(mod)


def mark_processed(ev, mark):
    if not hasattr(ev, 'processed'):
        ev.processed = []
    ev.processed.append(mark)

def has_processed(ip_server):
    url = 'http://'+ip_server+'/server-status'
    r = requests.get(url, allow_redirects=True)
    open('b.html', 'wb').write(r.content)

    for line_number, line in enumerate(fileinput.input('b.html', inplace=1)):
          if line_number == 18:
            linha = line
          else:
            cont = 1
    linha = linha.split("-")[1]
    linha = int(filter(str.isdigit, linha))
    return linha

def server_status(url):
    cn = httplib.HTTPConnection(url)
    cn.request("GET", "/server-status?auto")
    resp = cn.getresponse()
    if resp.status != 200:
        cn.close()
        raise ValueError('HTTP %s recebida de %s.' % (resp.status, url))
    raw = resp.read()
    cn.close()

    eita = raw.splitlines()
    load = float(eita[22].split(': ')[1])
    return load

def recv_message(conn):
    while True:
        """ try receiving message from process and if it doesn't it throws the eception which makes it continue
         to receive message"""
        try:
            received = conn.recv(1024)
            msg_token = received.decode('utf-8')
            print("received token: " + msg_token)
        except:
            continue
        """ if the received message has coordinator server stores ."""
        if "Coordinator: " in msg_token :
            le=msg_token.split()
            leader=le[1]
        """storing the index of the process id of the  cordinator."""
        process_index = process_sockets_list.index(conn)
        """  ths is used to know to whom the message is to be redirect if process sending the message is last in list
            then the next process is first process,otherwise the next process.as the processes are communicting in the ring"""
        if len(process_sockets_list)==process_index+1 :
            to_process=0
        else :
            to_process=process_index+1
        """ if the server unable to send the message to next process that means the process is stopped
        this will throws ann exception to remove the process from process_list and also removes the socket object in
        the process_sockets_list and closing that socket connection"""
        try :
            process_sockets_list[to_process].send(received)
            """redirecting the received message to next process in the ring"""
            print("sending :" + received.decode('utf-8'))
            """ if unable to send the message that means the that process is stopped ,so its socket object and
            process id's are remove from respective list."""
        except :
            """if the stopped process is not the coordinator then the message is redirected towards to the next process in the ring"""
            if process_list[to_process]!=leader :
                process_sockets_list[to_process+1].send(received)
                print("sending :" + received.decode('utf-8'))
            """closing the socket object of the stopped process."""
            process_sockets_list[to_process].close()
            """ removing the socket objec from the list"""
            process_sockets_list.remove(process_sockets_list[to_process])
            """removing the process id from proceeses list."""
            process_list.remove(process_list[to_process])
            continue
