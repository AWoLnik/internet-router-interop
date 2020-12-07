#!/usr/bin/env python

import argparse
import shutil
import os.path

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Node
from mininet.log import lg, LEVELS
from mininet.util import ipAdd

from p4_mininet import P4Host

def initParser():
    parser = argparse.ArgumentParser(description="Start a mininet for interoperability")
    parser.add_argument('--topo', '-t', help="choose a JSON file defining the topology",
                        type=argparse.FileType('r'), default='topo.json')
    parser.add_argument('--cli', help="enable mininet cli to debug",
                        action='store_true')
    parser.add_argument('--notest', help="do not run interop tests",
                        action='store_true')
    parser.add_argument('--verbosity', '-v', choices=list(LEVELS.keys()), default='output',
                        help='|'.join(LEVELS.keys()))
    return parser.parse_args()

def interopNet(topo):
    net = Mininet(host=P4Host)

    # Controllers have IPs from 10.10.0.0/16
    nextIP = 1
    ipBaseNum = 0x0a0a0000
    prefixLen = 16

    for sw_name in sorted(topo.get('switches', {}).keys()):
        sw_info = topo['switches'][sw_name]
        sw_cls = Node
        if 'class' in sw_info.keys():
            names = sw_info['class'].split('.')
            cls_module_name = '.'.join(names[:-1])
            cls_name = names[-1]
            cls_module = __import__(cls_module_name, fromlist=[cls_name])
            sw_cls = getattr(cls_module, cls_name)

        if 'prog' in sw_info.keys():
            # Resolve p4 program name conflicts
            prog_src = sw_info['prog']
            if not prog_src.startswith('/'):
                prog_src = os.path.join('/p4app', prog_src)
            prog_dst = os.path.join(os.path.dirname(prog_src), '_'.join(prog_src.split('/')))
            shutil.copy2(prog_src, prog_dst)
            sw_info['prog'] = prog_dst

        sw = net.addSwitch(sw_name, cls=sw_cls, **sw_info)
        if sw_info.get('enable_ctrl'):
            sw_ctrl = net.addHost('%s-c' % sw_name,
                                  ip=ipAdd(nextIP, ipBaseNum=ipBaseNum,
                                           prefixLen=prefixLen) + '/%s' % prefixLen)
            nextIP += 1
            net.addLink(sw_ctrl, sw)

    for h_name in sorted(topo.get('hosts', {}).keys()):
        h_info = topo['hosts'][h_name]
        net.addHost(h_name, **h_info)

    for link in topo.get('links', []):
        node1 = link[0]
        node2 = link[1]
        link_args = link[2] if len(link) > 2 else {}
        net.addLink(node1, node2, **link_args)
    return net

def interopTest(net):
    """Add test cases for interop
    """
    import time
    # Waiting for routing table converge
    # h2 = net.get("h2")
    # h2.cmd("arping -c1 10.0.0.1")
    # h1 = net.get("h1")
    # h1.cmd("arping -c1 10.0.1.2")
    time.sleep(10)
    # Pingall non-controller hosts
    hosts = [h for h in net.hosts if not h.name.endswith('-c')]
    print("First Ping Set")
    net.ping(hosts=hosts)
    print("Second Ping Set")
    net.ping(hosts=hosts)

def main():
    args = initParser()
    import json
    topo = json.load(args.topo)
    lg.setLogLevel(args.verbosity)
    net = interopNet(topo)
    net.start()
    for h in net.hosts:
        if not h.name.endswith('-c'):
            h.setDefaultRoute(h.params.get('defaultRoute'))
    if args.cli:
        CLI(net)
    if not args.notest:
        interopTest(net)
    for sw in net.switches:
        sw.printTableEntries()

    for sw in net.switches:
        # Assume everyone assigns the control-plane thread to a 'controller' attr
        sw_ctrl = getattr(sw, 'controller', None)
        if sw_ctrl is not None:
            sw_ctrl_join = getattr(sw_ctrl, 'join', None)
            if sw_ctrl_join is not None:
                lg.info('*** Stopping control-plane of %s\n' % sw.name)
                sw_ctrl_join()
                lg.info('*** Control-plane of %s stopped\n' % sw.name)

    # Issue: Mininet 2.3.0d1 in P4APP rc-2.0.0 has some bug to stop a mininet session
    # net.stop()

if __name__ == '__main__':
    main()
