import time
from threading import Thread
from scapy.all import Ether, IP, ARP, ICMP, sendp
from cpu_metadata import CPUMetadata, TYPE_CPU_METADATA
from async_sniff import Sniffer


from pwospf_protocol import PWOSPFHdr, PWOSPFHello, PWOSPFLSU, PWOSPFLSUWorker
from arp_protocol import ARPExpiryWorker, ARPPendingWorker, ARP_OP_REQ, ARP_OP_REPLY

ICMP_TYPE_ECHO  = 0x08
ICMP_TYPE_REPLY = 0x00
ARP_DST_MAC = 'ff:ff:ff:ff:ff:ff'

"""
MacLearning Controller

Runs the following threads:
    sniffer: Packet sniffer
    arp_pending_worker: Worker for queueing ARP requests
    arp_expiry_worker: Worker for handling ARP expiry and updates
    pwospf_lsu_worker: PWOSPF link state update worker
    pwospf_hello_worker: Per interface(port) PWOSPF hello protocol worker
"""

class MacLearningController(Thread):

    def __init__(self, switch, control_port=1, start_wait=1, timeout=1, arp_timeout=600, debug_mode=False):
        super(MacLearningController, self).__init__()
        self.switch = switch
        # timeout for pending packet
        self.timeout = timeout
        # Arp timeout
        self.arp_timeout = arp_timeout
        # Control interface
        self.iface = switch.intfs[control_port].name
        self.start_wait = start_wait # time to wait for the controller to be listenning

        self.routing_table = dict()
        self.arp_pending_worker = ARPPendingWorker(self.switch, timeout=self.timeout)
        self.arp_expiry_worker = ARPExpiryWorker(self.switch)
        self.pwospf_lsu_worker = PWOSPFLSUWorker(self.switch)
        self.sniffer = Sniffer(iface=self.iface, prn=self.PacketSwitch)
        self.debug_mode = debug_mode

    def ARPPacketHandler(self, pkt):
        if pkt[ARP].op == ARP_OP_REPLY:
        #    print("Handling ARP reply packets")
            # Update ARP table and send out pending packets
            self.arp_expiry_worker.updateArpTable(pkt[ARP].psrc, pkt[ARP].hwsrc)
        elif pkt[ARP].op == ARP_OP_REQ:
            #print("Handling ARPdd request packets from " + str(pkt[ARP].hwsrc) + " " + str(pkt[ARP].psrc) + " " + str(pkt[ARP].hwdst) + " " + str(pkt[ARP].pdst))
            # Update ARP table and send out pending packets
            self.arp_expiry_worker.updateArpTable(pkt[ARP].psrc, pkt[ARP].hwsrc)
            inport = self.switch.data_ports[pkt[CPUMetadata].ingressPort]
            port_mac = inport.intf.MAC()
            """
            https://stackoverflow.com/questions/50703738/what-is-the-meaning-of-the-scapy-arp-attributes
            hwdst is the destination hardware address
            psrc is Sender protocol address (SPA)
            hwdst is "Target hardware address (THA)
            pdst is "Target protocol address (TPA)"
            """
            pkt[Ether].dst = pkt[Ether].src
            pkt[Ether].src = port_mac

            pkt[ARP].op = ARP_OP_REPLY
            pkt[ARP].hwdst = pkt[ARP].hwsrc
            origpdst = pkt[ARP].pdst
            pkt[ARP].pdst = pkt[ARP].psrc
            if inport.hasIP(pkt[ARP].pdst):
                pkt[ARP].psrc = inport.get_ip()
            else:
                pkt[ARP].psrc = origpdst
            pkt[ARP].hwsrc = port_mac
            #print("Handling ARPdd request packets from " + str(pkt[ARP].hwsrc) + " " + str(pkt[ARP].psrc) + " " + str(pkt[ARP].hwdst) + " " + str(pkt[ARP].pdst))
            self.send(pkt, pkt[CPUMetadata].ingressPort)

    ####################################################################
    # Control plain requirement 1: Send ARP requests
    ####################################################################
    def generateARPPacket(self, pkt):
        egressport = pkt[CPUMetadata].egressPort
        dst_ip = pkt[IP].dst
        #print("&&&&&&&&&&&&&&&&&&&")
        #print(egressport)
        #print(self.switch.data_ports)
        #print("&&&&&&&&&&&&&&&&&&&")
        mac = self.switch.data_ports[egressport].intf.MAC()
        #print("Generating ARP Packets with egressport: " + str(egressport) + " dst_ip: " + str(dst_ip) + " srcmac " + str(mac))
        return Ether(dst=ARP_DST_MAC, src=mac) / CPUMetadata()\
            / ARP(hwlen=6, plen=4, op=ARP_OP_REQ, hwsrc=mac, psrc=self.switch.data_ports[egressport].get_ip(),\
                  hwdst='00:00:00:00:00:00', pdst=dst_ip)

    ####################################################################
    # Control plain requirement 5: Responding to ICMP echo requests
    ###################################################################
    def ICMPPacketHandler(self, pkt):
        #print("Handling ICMP request packets")
        #print(pkt[ICMP].type)
        #print(pkt[ICMP].code)
        #print(pkt[IP].src)
        #print(pkt[IP].dst)
        #print(self.switch.name)
        #print(pkt[Ether].src)
        #print(pkt[Ether].dst)
        #print(pkt[CPUMetadata].padding)
        #pkt[ICMP].type = ICMP_TYPE_ECHO
        #pkt[ICMP].code = 0
        if(pkt[ICMP].type == 0):
            pkt[ICMP].type = 8
        #    self.send(pkt, pkt[CPUMetadata].egressPort)
        #    return
        if pkt[ICMP].type == ICMP_TYPE_ECHO and pkt[ICMP].code == 0:
            #knownips = [p.get_ip() for p in self.switch.data_ports.values()]
            #print('ICMP echo to %s:\n ' % (pkt[IP].dst) + self.switch.name + " " + str(knownips))
            #for kip in knownips:
            #    print(kip)
            if pkt[IP].dst in [p.get_ip() for p in self.switch.data_ports.values()]:
                pkt[ICMP].type = 0
                pkt[ICMP].chksum = None
                ip_src = pkt[IP].src
                pkt[IP].src = pkt[IP].dst
                pkt[IP].dst = ip_src
                mac_src = pkt[Ether].src
                pkt[Ether].src = pkt[Ether].dst
                pkt[Ether].dst = mac_src
                #print('Send ICMP Reply from %s to port %d:\n' % (self.switch.name, pkt[CPUMetadata].ingressPort))
                self.send(pkt, pkt[CPUMetadata].ingressPort)
            else:
                # The data plane does not know what to do with it and send to cpu
                #print("This ICMP request to " + str(pkt[IP].dst) +  " is cached and asking for ARP now")
                arp_entry = self.arp_expiry_worker.arp_table.get(pkt[IP].dst)
                if arp_entry is None:
                    egressport = pkt[CPUMetadata].egressPort
                    self.send(self.generateARPPacket(pkt), egressport)
                self.arp_pending_worker.push_request(pkt, time.time() + self.timeout)
        else:
            print("Other ICMP requests not implemented yet")
            print(pkt[ICMP].type)
            print(pkt[ICMP].code)
            print(pkt[IP].src)
            print(pkt[IP].dst)
            print(self.switch.name)
            print(pkt[Ether].src)
            print(pkt[Ether].dst)
            print(pkt[CPUMetadata].padding)

    def OSPFPacketHandler(self, pkt):
        if PWOSPFHello in pkt:
            ingress_hello_worker = self.switch.data_ports[pkt[CPUMetadata].ingressPort]
            nip = pkt[IP].src
            nid = pkt[PWOSPFHdr].routerid
            helloint = pkt[PWOSPFHello].helloint
            netmask = pkt[PWOSPFHello].netmask
            #print(self.switch.name + " Handling OSPF Hello packets with srcip: " + str(nip) + " with routerid " + str(nid) + " and add neighbor to port " + str(pkt[CPUMetadata].ingressPort))
            ingress_hello_worker.addNeighbor(nid, nip, netmask, helloint)
        elif PWOSPFLSU in pkt:
            #print("Handling OSPF LSU packets")
            self.pwospf_lsu_worker.handleLSU(pkt)


    ###################################################################################
    # Control plain requirement 7: Handling corrupted or otherwise incorrect IP packets
    # Control plain requirement 9: Handling all packets addressed directly to the router
    ###################################################################################
    def PacketSwitch(self, pkt):
        if self.debug_mode:
        # print every packet detail in debug mode
            pkt.show2()
        if CPUMetadata not in pkt or pkt[CPUMetadata].fromCpu == 1:
            return
        if ARP in pkt:
            self.ARPPacketHandler(pkt)
        elif PWOSPFHdr in pkt:
            if pkt[PWOSPFHdr].areaid == self.switch.area_id :
                if pkt[PWOSPFHdr].routerid == self.switch.router_id:
                    return
                self.OSPFPacketHandler(pkt)
            else:
                print pkt[PWOSPFHdr].routerid
                print self.switch.router_id
                raise Exception("Wrong area ID or routerID!")
        elif ICMP in pkt:
            self.ICMPPacketHandler(pkt)

    def send(self, pkt, output, multicast=0, *args, **override_kwargs):
        if CPUMetadata not in pkt:
            pkt.type = TYPE_CPU_METADATA
            pkt.payload = CPUMetadata() / pkt.payload
        pkt[CPUMetadata].fromCpu = 1
        pkt[CPUMetadata].multiCast = multicast
        pkt[CPUMetadata].egressPort = output

        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(pkt, *args, **kwargs)

    def run(self):
        # listen on control port
        self.sniffer.start()
        self.arp_pending_worker.start()
        self.arp_expiry_worker.start()
        self.pwospf_lsu_worker.start()
        for key, helloworker in self.switch.data_ports.items():
            helloworker.start()

    def start(self, *args, **kwargs):
        super(MacLearningController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.switch.showCounters()
        self.sniffer.stop()
        self.arp_expiry_worker.stop()
        self.pwospf_lsu_worker.stop()
        self.arp_pending_worker.stop()
        super(MacLearningController, self).join(*args, **kwargs)
