import time
from threading import Lock
from scapy.all import sendp
from scapy.fields import ByteField, ByteEnumField, LenField, IPField, XShortField, ShortField, LongField,  FieldLenField, PacketListField
from cpu_metadata import CPUMetadata
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import Ether, IP, DestIPField
from Djikstra import Graph
from protocol import ProtocolWorker, ip_to_hex, hex_to_ip, get_prefix
from scapy.utils import checksum
import struct

PWOSPF_VERSION = 0x02
PROTO_PWOSPF = 0x59
ALLSPFRouters = '224.0.0.5'



class PWOSPFHdr(Packet):
    name = "PWOSPFHeader"
    fields_desc = [
        ByteField('version', PWOSPF_VERSION),
        ByteEnumField('type', 1, {1: "Hello", 4:"LSU"}),
        LenField('len', None, adjust=lambda x: x + 24),
        IPField('routerid', '1.1.1.1'), # 32 bit router id, use the IP address of the 0th interface
        IPField('areaid', '0.0.0.0'),
        XShortField('checksum', None),
        ShortField('autype', 0),
        LongField('authentication', 0)
    ]
    def post_build(self, p, pay):
        # See <http://tools.ietf.org/html/rfc5613>
        p += pay
        if self.checksum is None:
            # Checksum is calculated without authentication data
            # Algorithm is the same as in IP()
            ck = checksum(p[:16] + p[24:])
            p = p[:12] + struct.pack("!H", ck) + p[14:]
        return p


class PWOSPFHello(Packet):
    name = "PWOSPFHello"
    fields_desc = [
        IPField('netmask', '255.255.255.0'),
        ShortField('helloint', 5),
        ShortField('padding', 0)
    ]

class PWOSPFLSA(Packet):
    name = "PWOSPFLSA"
    fields_desc = [
        IPField('subnet', '10.0.0.0'),
        IPField('mask', '255.255.255.0'),
        IPField('routerid', '1.1.1.1')
    ]
    def extract_padding(self, s):
        return '', s

class PWOSPFLSU(Packet):
    name = "PWOSPFLSU"
    fields_desc = [
        ShortField('seq', 0),
        ShortField('ttl', 32),
        FieldLenField('numlsa', None, fmt='!I', count_of='lsalist'),
        PacketListField('lsalist', None, PWOSPFLSA,
                        count_from=lambda pkt: pkt.numlsa,
                        length_from=lambda pkt: 12 * pkt.numlsa)
    ]
    def extract_padding(self, s):
        return '', s


bind_layers(IP, PWOSPFHdr, proto=PROTO_PWOSPF)
bind_layers(PWOSPFHdr, PWOSPFHello, type=1)
bind_layers(PWOSPFHdr, PWOSPFLSU, type=4)
DestIPField.bind_addr(PWOSPFHdr, ALLSPFRouters)



class LinkStateDB():

    def __init__(self, lsuint):
        self.lsuint = lsuint
        self.linkstateDB = dict()
        self.lock = Lock()
        self.lsutimeout = self.lsuint * 3

    def remove_timeout(self):
        for router_id, ls_adv in self.linkstateDB.items():
            if time.time() > ls_adv['lasttime'] + self.lsutimeout:
                # Remove link state entry after LSU_TIMEOUT
                del self.linkstateDB[router_id]

    def updateEntry(self, router_id, seq, networks):
        # FIXME add mutex?
        self.linkstateDB[router_id] = {
            'seq': seq,
            'lasttime': time.time(),
            'networks': networks
        }

    def exists(self, router_id):
        return router_id in self.linkstateDB

    def get_seq(self, router_id):
        return self.linkstateDB[router_id]['seq']

    def get_lasttime(self, router_id):
        return self.linkstateDB[router_id]['lasttime']

    def get_networks(self, router_id):
        return self.linkstateDB[router_id]['networks']

    def compute_shortest_path(self, target_router_id):
        g = Graph()
        networks = {}
        for router_id, lsa in self.linkstateDB.items():
            for neighbors in lsa['networks']:
                subnet, netmask, nid = neighbors
                g.add_edge(router_id, nid)
                netaddr = get_prefix(subnet, netmask)
                if netaddr not in networks:
                    networks[netaddr] = set()
                networks[netaddr].add(router_id)
        next_hops = g.fetch_next_hop(target_router_id)
        return next_hops, networks

"""
PWOSPF Link state update worker
Link state updates are sent periodically every
  LSUINT seconds (default value of 30)

"""
class PWOSPFLSUWorker(ProtocolWorker):

    def __init__(self, switch):
        ProtocolWorker.__init__(self, switch)

        self.lastlsutime = 0
        self.lsdb = LinkStateDB(lsuint = self.switch.lsuint)
        self.seq = 0
        self.lsuint = self.switch.lsuint

    def _run(self):
        self.running = True
        while True:
            if self.stop_event and self.stop_event.is_set():
                break
            if time.time() >= self.lastlsutime + self.lsuint:
                # Flood the LSU
                self.floodLSU()
                self.lastlsutime = time.time()
            self.lsdb.remove_timeout()

    def generateLSUPacket(self, lsalist):
        return Ether() / IP() / PWOSPFHdr(routerid=self.switch.router_id, areaid=self.switch.area_id) \
            / PWOSPFLSU(seq=self.seq, lsalist=lsalist)

    def floodLSU(self):
        lsalist = []
        for p in self.switch.data_ports.values():
            if not len(p.neighbors):
                lsalist.append(PWOSPFLSA(subnet=p.get_subnet(), mask=p.get_netmask_hex(), routerid='0.0.0.0'))
            else:
                for neighbor in p.neighbors.keys():
                    router_id, ipaddr = neighbor
                    lsalist.append(PWOSPFLSA(subnet=p.get_subnet(ipaddr), mask=p.get_netmask_hex(), routerid=router_id))

        #print(self.switch.name + " Flooding the LSU message" + str(lsalist))
        if(self.switch.name == "sw2" or self.switch.name == "sw4"):
            import time
            time.sleep(2)
        self.lsdb.updateEntry(self.switch.router_id, self.seq, [(lsa.subnet, lsa.mask, lsa.routerid) for lsa in lsalist])
        self.seq += 1
        self.switch.controller.send(self.generateLSUPacket(lsalist), 1, multicast=True)

    def handleLSU(self, pkt):
        rid = pkt[PWOSPFHdr].routerid
        if rid == self.switch.router_id or (self.lsdb.exists(rid) and pkt[PWOSPFLSU].seq == self.lsdb.get_seq(rid)):
            return

        # update lsu in database
        #count = 0
        #if(self.switch.name == "sw1"):
        #    print(self.switch.name + " Handling lsa " + str(pkt[PWOSPFLSU].numlsa) + " " + str(pkt[PWOSPFLSU].lsalist))
        #    #print(str(count) + " " + str(self.switch.name) + " " + str(lsa.subnet) + " " + str(lsa.mask) + " " + str(lsa.routerid))
        #    count = count + 1
        self.lsdb.updateEntry(rid, pkt[PWOSPFLSU].seq, [(lsa.subnet, lsa.mask, lsa.routerid) for lsa in pkt[PWOSPFLSU].lsalist])

        pkt[PWOSPFLSU].ttl -= 1
        for port_num, pi in self.switch.data_ports.items():
            if not pi.neighbors or port_num == pkt[CPUMetadata].ingressPort:
                continue
            if pkt[PWOSPFLSU].ttl > 0:
                self.switch.controller.send(pkt, port_num)
        # update forwarding table
        self.updateRoutingTable()

    ####################################################################################################
    # Control plain requirement 8: Building the forwarding table via a dynamic routing protcol (PWOSPF)
    ####################################################################################################
    def updateRoutingTable(self):
        # Calculate next hops based on link state DB
        next_hops, networks = self.lsdb.compute_shortest_path(self.switch.router_id)

        #for netaddr, nodes in networks.items():
        #    if len(nodes) == 1:
        #        dst = nodes.pop()
        #        if dst == self.switch.router_id:
        #            nhop = None
        #        else:
        #            nhop, _ = next_hops.get(dst, (None, None))
        #    elif len(nodes) == 2:
        #        n1, n2 = nodes
        #        if self.switch.router_id in nodes:
        #            dst = nhop = (n2 if n1 == self.switch.router_id else n1)
        #        else:
        #            dst = (n1 if next_hops[n1][1] < next_hops[n2][1] else n2)
        #            nhop, _ = next_hops[dst]
        #    for pn, p in self.switch.data_ports.items():
        #        gateway = p.hasNeighbor(nhop)
        #        if get_prefix(p.get_ip(), p.get_netmask_hex()) == netaddr:
        #            gateway = '0.0.0.0'
        #        if gateway is not None:
        #            r = (netaddr, gateway, pn)
        #            self.switch.pending_pwospf_table[netaddr] = r

        #if self.switch.name == "sw1":
        #    print("###################3")
        #    print(self.switch.name + " " +  str(next_hops))
        #    print(networks)
        #    print("###################3")
        for netaddr, nodes in networks.items():
            find_min = 1000000 # some random large number
            min_label = None
            try:
                for node in nodes:
                    #print(str(node))
                    if next_hops[node][1] < find_min:
                        min_label = node
                        find_min = next_hops[node][1]
                #print("min_label" + str(min_label))
                if(min_label == self.switch.router_id):
                    next_hop = None
                else:
                    next_hop = next_hops[min_label]
                #print("next_hop is set to be: " + str(next_hop))
            except KeyError:
                next_hop = None
        #    print("857384579        " + str(next_hop))
            for pn, p in self.switch.data_ports.items():
                nexthop = p.hasNeighbor(next_hop)
                #if self.switch.name == "sw1":
                #    print("^^^^^^^^^^^^^^^^^^^^^6")
                #    print(self.switch.name)
                #    print(p.show_neighbors())
                #    print(pn)
                #    print(next_hop)
                #    print(nexthop)
                #    print("^^^^^^^^^^^^^^^^^^^^^6")
                #if next_hop is not None:
                #    nexthop = next_hop[0]
                #else:
                #    nexthop = None
                # Send out nexthop '0.0.0.0' for direct connection
                if get_prefix(p.get_ip(), p.get_netmask_hex()) == netaddr:
                    # default route
                    nexthop = '0.0.0.0'
                if nexthop is not None:
                    r = (netaddr, nexthop, pn)
                    self.switch.pending_pwospf_table[netaddr] = r
                #print("nexthop " + str(nexthop))
        #print("&&&&&&&&&&&&&&&")
        #print(self.switch.name)
        #print(self.switch.pending_pwospf_table)
        #print("&&&&&&&&&&&&&&&")
        #Update the routes
        for netaddr in self.switch.pending_pwospf_table:

        ####################################################################
        # Control plain requirement 9: Support static routing table entries in addition to the routes computed by PWOSPF
        ###################################################################
            if netaddr in self.switch.static_routes:
                continue
            r = self.switch.pending_pwospf_table[netaddr]
            if r != self.switch.pwospf_table.get(netaddr):
                if netaddr in self.switch.pwospf_table:
                    print("Remove route for " + str(netaddr))
                    self.switch.removeRoute(netaddr)
                self.switch.addRoute(r[0], r[2], r[1])
                print("Adding route for " + str(r[0]) + " " + str(r[2]) + " " + str(r[1]))
                self.switch.pwospf_table[netaddr] = r
        to_remove = []
        for route in self.switch.pwospf_table:
            if route not in self.switch.pending_pwospf_table:
                to_remove.append(route)
        for route in to_remove:
            del self.switch.pwospf_table[route]
        self.switch.pending_pwospf_table.clear()

"""
PWOSPF Interface
Takes care of adding neighbors/remove expired neighbors/send hello packets periodically
  32 bit ip address  - IP address of associated interface
  32 bit mask mask   - subnet mask of associated interface
  16 bit helloint    - interval in seconds between HELLO broadcasts
  list [
    32 bit neighbor id - ID of neighboring router.
    32 bit neighbor ip - IP address of neighboring router's interface this
                         interface is directly connected to.
  ]
"""

class PWOSPFHelloWorker(ProtocolWorker):

    def __init__(self, intf, switch=None, control_port=1, port_number=None, ipaddr='0.0.0.0', netmask=0x00000000, prefixlen=0, helloint=1, defaultPrefixlen=24, **kwargs):
        ProtocolWorker.__init__(self, switch)
        self.intf = intf
        if port_number is not None:
            self.port_number = port_number
        else:
            self.port_number = self.switch.ports[self.intf]

        self.prefixlen = prefixlen
        self.defaultPrefixlen = defaultPrefixlen
        self.lock = Lock()

        self.router_id = self.switch.router_id
        self.area_id = self.switch.area_id
        self.ipaddr = ipaddr
        self.netmask = netmask
        self.helloint = helloint
        self.neighbors = dict()
        self.lasthellotime = 0
        self.control_port = control_port

    def show_neighbors(self):
        return self.neighbors

    def config(self, ip=None, helloint=None, **kwargs):
        print(ip)
        if '/' in ip:
            self.ipaddr, self.prefixlen = ip.split('/')
            self.prefixlen = int(self.prefixlen)
        else:
            self.ipaddr = ip
            self.prefixlen = self.defaultPrefixlen
        self.netmask = 0xffffffff ^ (0xffffffff >> self.prefixlen)
        if helloint is not None:
            self.helloint = helloint

    def get_mac(self):
        return self.intf.MAC()

    def get_ip(self):
        return str(self.ipaddr)

    def get_ip_hex(self):
        return ip_to_hex(self.ipaddr)

    def get_subnet(self, ipaddr=None, netmask=None):
        return hex_to_ip(self.get_ip_hex_masked(ipaddr, netmask))

    def get_netmask_hex(self):
        return hex_to_ip(self.netmask)

    def get_ip_hex_masked(self, ipaddr=None, netmask=None):
        if netmask is None:
            netmask = self.netmask
        if ipaddr is None:
            ipaddr = self.ipaddr
        return ip_to_hex(ipaddr) & netmask

    def hasIP(self, ipaddr):
        return self.get_ip_hex_masked(ipaddr) == self.get_ip_hex_masked()

    def hasNeighbor(self, rid):
        if rid is not None:
            rid = rid[0]
        for neigh in self.neighbors:
            if neigh[0] == rid:
                return neigh[1]
        return None

    def send(self, pkt, output, multicast=0, *args, **override_kwargs):
        from cpu_metadata import CPUMetadata, TYPE_CPU_METADATA
        if CPUMetadata not in pkt:
            pkt.payload = CPUMetadata() / pkt.payload
            pkt.type = TYPE_CPU_METADATA
        pkt[CPUMetadata].fromCpu = 1
        pkt[CPUMetadata].multiCast = multicast
        pkt[CPUMetadata].egressPort = output
        iface = self.switch.intfs[self.control_port].name

        kwargs = dict(iface=iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(pkt, *args, **kwargs)

    def generateHelloPacket(self):
        #print("Generating hello packets from " + str(self.switch.name) + " " + str(self.get_mac()) + " " + self.get_ip())
        return Ether(src=self.get_mac(), dst='ff:ff:ff:ff:ff:ff') / IP(src=self.get_ip()) / \
               PWOSPFHdr(routerid=self.router_id, areaid=self.area_id) / \
               PWOSPFHello(netmask=self.get_netmask_hex(), helloint=self.helloint)

    def _run(self):
        self.running = True
        while True:
            if self.stop_event and self.stop_event.is_set():
                break
            if time.time() >= self.lasthellotime + self.helloint:
                # generate hello packet
                #print("Sending hello packets")
                self.send(self.generateHelloPacket(), self.port_number)
                self.lasthellotime = time.time()
            # Remove expired neighbor
            self.lock.acquire()
            for n, lasttime in self.neighbors.items():
                timeout = lasttime[1] * 3
                # Unknown bug here: https://github.com/stefanfoulis/django-image-filer/issues/37
                #print("Checking here " + str(lasttime[0]) + " " + str(time.time() + " " + str(lasttime[1]))
                if time.time() > lasttime[0] + timeout:
                    print("deleting neighbor " + str(self.neighbors[n]) + " for switch " + self.switch.name)
                    del self.neighbors[n]
            self.lock.release()

    """
    If the packet is from a yet to be identified neighbor and no other neighbors have been
    discovered off of the incoming interface, the router will add the neighbor to
    the interface.  If the packet is from a known neighbor, the router will mark
    the time the packet was received to track the uptime of its neighbor.
    """
    def addNeighbor(self, nid, nip, netmask, helloint):
        if netmask != self.get_netmask_hex() or helloint != self.helloint:
            return
        self.lock.acquire()
        self.neighbors[(nid, nip)] = (time.time(), helloint)
        self.lock.release()

        #print(self.switch.name + " " + str(self.port_number) + "Adding neighbor here: " + str(nid) + " " + str(nip))
