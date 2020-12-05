from p4_mininet import P4RuntimeSwitch
from p4_program import P4Program
from pwospf_protocol import PWOSPFHelloWorker
from controller import MacLearningController
"""

  32 bit router ID
  32 bit area ID
  16 bit lsuint    - interval in seconds between link state update broadcasts

https://github.com/yale-build-a-router/internet-router-interop
"""

class PWOSPFRouter(P4RuntimeSwitch):
    def __init__(self, name, router_id='1.1.1.1', area_id='0.0.0.0', lsuint=30, startup_config=dict(), *opts, **kwargs):
        self.router_id = str(router_id)
        self.area_id = str(area_id)
        self.lsuint = lsuint
        self.data_ports = dict()
        self.static_routes = dict()
        self.pwospf_table = dict()
        self.pending_pwospf_table = dict()
        self.controller = None
        prog = P4Program('/p4app/l2switch.p4')

        sw_path = 'simple_switch_grpc'
        enable_grpc = True

        self.control_args = dict()
        if 'control_args' in kwargs:
            self.control_args = kwargs['control_args']
            del kwargs['control_args']
        self.control_port = self.control_args.get('control_port', 1)

        self.startup_config = startup_config

        kwargs.update({
            'enable_grpc': enable_grpc,
            'cli_path': 'simple_switch_CLI',
            'sw_path': sw_path,
            'program': prog,
            'start_controller': True,
        })

        P4RuntimeSwitch.__init__(self, name, *opts, **kwargs)

    def showCounters(self):
        cpkt, cbyte = self.readCounter('MyIngress.arpIngressCounter', self.control_port)
        print('\tARP ingress counter: %d pkts, %d bytes' % (cpkt, cbyte))
        cpkt, cbyte = self.readCounter('MyEgress.arpEgressCounter', self.control_port)
        print('\tARP Egress counter: %d pkts, %d bytes' % (cpkt, cbyte))
        cpkt, cbyte = self.readCounter('MyIngress.ipIngressCounter', self.control_port)
        print('\tIp ingress counter: %d pkts, %d bytes' % (cpkt, cbyte))
        cpkt, cbyte = self.readCounter('MyEgress.ipEgressCounter', self.control_port)
        print('\tIp egress counter: %d pkts, %d bytes' % (cpkt, cbyte))
        cpkt, cbyte = self.readCounter('MyIngress.ctrlPlaneCounter', self.control_port)
        print('\tcontrol plane counter: %d pkts, %d bytes' % (cpkt, cbyte))

    def deleteTableEntry(self, entry=None,
                         table_name=None, match_fields=None, priority=None):
        pass
        #print("Table entry should be removed here!!!!")
        #print(table_name)
        #print(match_fields)

    def addRoute(self, ipaddrprefix, next_hop, nexthop, fake=False):
        if not fake:
            ip, prefixlen = ipaddrprefix.split('/')
            self.insertTableEntry(table_name='MyIngress.routing_table',
                                  match_fields={'hdr.ipv4.dstAddr': [ip, int(prefixlen)]},
                                  action_name='MyIngress.ipv4_forward',
                                  action_params={'port': next_hop, 'nexthop': nexthop})

    def removeRoute(self, ipaddrprefix):
        ip, prefixlen = ipaddrprefix.split('/')
        self.deleteTableEntry(table_name='MyIngress.routing_table',
                              match_fields={'hdr.ipv4.dstAddr': [ip, int(prefixlen)]})

    def config(self):
        # Launch PWOSPFHelloWorkers for each data port
        self.data_ports = {
            p: PWOSPFHelloWorker(self.intfs[p], switch=self, control_port=self.control_port) for p in self.intfs.keys() \
            if p not in [0, self.control_port]
        }

        # Configure the ip and subnet for all interfaces
        intf_config = self.startup_config.get('interfaces', dict())
        for p in self.data_ports.keys():
            print(p)
            print(intf_config)
            self.data_ports[p].config(**intf_config.get(str(p), dict()))

        # Configure static routes
        self.static_routes = self.startup_config.get('static_routes', dict())
        for ipaddrprefix, route in self.static_routes.items():
            self.addL3Route(str(ipaddrprefix), route[0], route[1])

        # Set 1 as multicast groupID to all ports
        self.flood_mgid = 1
        data_ports = list(self.data_ports.keys())
        self.addMulticastGroup(mgid=self.flood_mgid, ports=data_ports)
        # Reference:    https://github.com/p4lang/behavioral-model/blob/master/docs/simple_switch.md
        #               https://github.com/p4lang/behavioral-model/issues/667
        # Set port id as multicast groupID to ports except that port
        for port in data_ports:
            flood_ports = [p for p in data_ports if p != port]
            self.addMulticastGroup(mgid=port, ports=flood_ports)

        for port_num, port in self.data_ports.items():
            self.insertTableEntry(table_name='MyIngress.local_mac_table',
                                  match_fields={'standard_metadata.egress_spec': port_num},
                                  action_name='MyIngress.update_src_mac',
                                  action_params={'srcEth': port.intf.MAC()})
            # Initialize local ip table
            self.insertTableEntry(table_name='MyIngress.local_ip_table',
                                  match_fields={'hdr.ipv4.dstAddr': port.get_ip()},
                                  action_name='MyIngress.send_to_cpu',
                                  action_params={'padding': 0x05})

    def start(self, controllers):
        super(PWOSPFRouter, self).start(controllers)
        self.config()
        self.controller = MacLearningController(self, **self.control_args)
        self.controller.start()

    def stop(self):
        self.showCounters()
        for p in self.data_ports.values():
            p.stop()
        self.controller.join()
        super(PWOSPFRouter, self).stop()
