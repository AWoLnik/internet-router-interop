"""
Reference: https://www.gsp.com/cgi-bin/man.cgi?section=4&topic=arp
"""


import time
from multiprocessing import Queue
from threading import Lock
from scapy.all import Ether, IP
from cpu_metadata import CPUMetadata
from protocol import ProtocolWorker
from scapy.all import ICMP

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

#def makeMask(n):
#    "return a mask of n bits as a long integer"
#    return (2L<<n-1) - 1
#
#def dottedQuadToNum(ip):
#    "convert decimal dotted quad string to long integer"
#    return struct.unpack('L',socket.inet_aton(ip))[0]
#
#def networkMask(ip,bits):
#    "Convert a network address to a long integer"
#    return dottedQuadToNum(ip) & makeMask(bits)
#
#def addressInNetwork(ip,net):
#   "Is an address in a network"
#   return ip & net == net

#address = dottedQuadToNum("192.168.1.1")
#networka = networkMask("10.0.0.0",24)
#networkb = networkMask("192.168.0.0",24)
#print (address,networka,networkb)
#print addressInNetwork(address,networka)
#print addressInNetwork(address,networkb)

#################################################################################
# Control plane requirement 4: Queuing packets pending ARP replies
################################################################################
class ARPPendingWorker(ProtocolWorker):
    def __init__(self, switch, timeout=30):
        ProtocolWorker.__init__(self, switch, timeout)
        self.pending_queue = Queue()
        # self.lock = Lock()
        # Since multiprocessing queue is thread-safe, process-safe, no need to add lock here

    def push_request(self, pkt, expiry):
        self.pending_queue.put((pkt, expiry))

    def pop_request(self):
        pkt, time_to_expiry = self.pending_queue.get()
        return pkt, time_to_expiry

    def in_subnet(self, net, ip):
        ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
        netstr, bits = net.split('/')
        netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
        mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
        return (ipaddr & mask) == (netaddr & mask)
        #ip = subnet.split('/')[0]
        #mask = int(subnet.split('/')[1])
        #print("addr here " + addr)
        #address = dottedQuadToNum(addr)
        #network = networkMask(ip, mask)
        #return addressInNetwork(address, network)


    def _run(self):
        self.running = True
        while True:
            if self.stop_event and self.stop_event.is_set():
                break
            if not self.pending_queue.empty():
                pkt, time_to_expire = self.pop_request()
                if time.time() > time_to_expire:
                    print("ARP request timeout!")
                    if ICMP in pkt:
                        print("Sending ICMP host unreachable")
                        pkt[ICMP].type = 3
                        pkt[ICMP].code = 1
                        pkt[ICMP].chksum = None
                        ip_src = pkt[IP].src
                        pkt[IP].src = pkt[IP].dst
                        pkt[IP].dst = ip_src
                        mac_src = pkt[Ether].dst
                        pkt[Ether].src = pkt[Ether].dst
                        pkt[Ether].dst = mac_src
                        #print('Send ICMP Reply from %s to port %d:\n' % (self.switch.name, pkt[CPUMetadata].ingressPort))
                        self.switch.controller.send(pkt, pkt[CPUMetadata].ingressPort)
                else:
                    #print("**************************###################################")
                    #print(self.switch.name + " " + str(self.switch.pwospf_table))
                    #print("########################*************************###########")
                    sent = False
                    if ICMP in pkt:
                        for net, nexthops in self.switch.pwospf_table.items():
                            if self.in_subnet(net, pkt[IP].dst):
                                arp_entry = self.switch.controller.arp_expiry_worker.arp_table.get(nexthops[1])
                                if arp_entry is None:
                                    break
                                else:
                                    pkt[Ether].dst = arp_entry['mac']
                                    #print("Sending this ICMP to " + str(nexthops[1]))
                                    self.switch.controller.send(pkt, pkt[CPUMetadata].egressPort)
                                    sent = True
                    if not sent:
                        arp_entry = self.switch.controller.arp_expiry_worker.arp_table.get(pkt[IP].dst)
                        if arp_entry is None:
                            self.push_request(pkt, time_to_expire)
                        else:
                            pkt[Ether].dst = arp_entry['mac']
                            #if ICMP in pkt:
                                #print("Sending this ICMP to " + str(pkt[IP].dst))
                            self.switch.controller.send(pkt, pkt[CPUMetadata].egressPort)

#################################################################################
# Control plane requirement 2: Updating entries in the hardware ARP cache
# Control plane requirement 3: Timing out entries in the hardware ARP cache
################################################################################

class ARPExpiryWorker(ProtocolWorker):
    def __init__(self, switch, timeout=300):
        ProtocolWorker.__init__(self, switch, timeout)
        self.arp_table = dict()
        # Add lock for access of the arp table as it could be accessed by multiple threads
        self.lock = Lock()

    def updateArpTable(self, ip, mac):
        # Remove the old arp entry
        #print("Updating ARP table with ip: " + str(ip) + " mac: " + str(mac) + " " + self.switch.name)
        self.lock.acquire()
        remove_flag = False
        if ip in self.arp_table:
            remove_flag = True
            #print("Removing old arp entry for ip: " + str(ip))
            self.switch.deleteTableEntry(table_name='MyIngress.arp_table', match_fields={'meta.nexthop': ip})
        # Update software arp table
        self.arp_table[ip] = {
            'mac': mac,
            'expiry': time.time() + self.timeout
        }
        # Update hardware arp table
        if not remove_flag:
            #print("The new nexthop that should be inserted is: " + str(ip))
            self.switch.insertTableEntry(table_name='MyIngress.arp_table',
                                     match_fields={'meta.nexthop': ip},
                                     action_name='MyIngress.update_dst_mac',
                                     action_params={'dstEth': mac})
        self.lock.release()

    def _run(self):
        self.running = True
        while True:
            if self.stop_event and self.stop_event.is_set():
                break
            arp_table_snapshot = self.arp_table.copy()
            for entry in arp_table_snapshot:
                if arp_table_snapshot[entry]['expiry'] < time.time():
                # This lock require/release could be more efficient in better granularity
                    self.lock.acquire()
                    try:
                        if self.arp_table[entry]['expiry'] < time.time():
                            #print("ARP entry for ip: " + str(entry) + " expired, removing now...")
                            del self.arp_table[entry]
                            self.switch.deleteTableEntry(table_name='MyIngress.arp_table', match_fields={'meta.nexthop': entry})
                    except KeyError:
                        # arp table has been updated
                        pass
                    self.lock.release()

