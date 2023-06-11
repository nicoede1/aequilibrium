import requests
import fileinput
import http.client as httplib
import os, ssl


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

#mark process to avoid overload
def mark_processed(ev, mark):
    if not hasattr(ev, 'processed'):
        ev.processed = []
    ev.processed.append(mark)

#function to retrieve and filter the metrics from the servers
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
    cpu = str(eita[16]).split(': ')[1]
    cpu = float(cpu.split("'")[0])
    load = str(eita[21]).split(': ')[1]
    load = float(load.split("'")[0])
    total = load + (1/cpu) #returns the formula specified tput + 1/cpu usage
    return total

