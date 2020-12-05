/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//   Provide a routing table that can store IP address/prefix pairs with their associated port and next-hop IP address.
//   Use the routing table to perform a longest prefix match on destination IP addresses and return the appropriate egress port and next-hop address (or 0.0.0.0 for a directly attached destination).
//   NOTE: We will use a ternary match table for the routing table because LPM tables are not fully supported by SDNet yet.
//   Provide an ARP table that can store at least 64 entries. This will accept an IP address as a search key and will return the associated MAC address (if found). This table is modified by the software, which runs its own ARP protocol.
//   Provide a “local IP address table”. This will accept an IP address as a search key and will return a signal that indicates whether the correspond address was found. This table is used to identify IP addresses that should be forwarded to the CPU.
//   Decode incoming IP packets and perform the operations required by a router. These include (but are not limited to):
//       verify that the existing checksum and TTL are valid
//       look up the next-hop port and IP address in the route table
//       look up the MAC address of the next-hop in the ARP table
//       set the src MAC address based on the port the packet is departing from
//       decrement TTL
//       calculate a new IP checksum
//       transmit the new packet via the appropriate egress port
//       local IP packets (destined for the router) should be sent to the software
//       PWOSPF packets should be sent to the software
//       packets for which no matching entry is found in the routing table should be sent to the software
//       any packets that the hardware cannot deal with should be forwarded to the CPU. (e.g. not Version 4 IP)
//   Provide counters for the following:
//       IP packets
//       ARP packets
//       Packets forwarded to the control-plane

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;

const bit<32> MAX_PORTS = 65;
const port_t CPU_PORT = 0x1;
const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;
//https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_IPV4         = 0x0800;
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<8> TYPE_PWOSPF = 0x59;
const bit<8> TYPE_ICMP = 0x01;
const bit<8> ICMP_TYPE_ECHO  = 0x08;
const bit<8> ICMP_TYPE_REPLY = 0x00;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    macAddr_t srcEth;
    ipv4Addr_t srcIP;
    macAddr_t dstEth;
    ipv4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

header cpu_metadata_t {
    bit<1> fromCpu;
    bit<1> multiCast;
    bit<12> padding;
    port_t ingressPort;
    port_t egressPort;
    bit<16> origEtherType;
}

struct headers {
    ethernet_t        ethernet;
    arp_t             arp;
    ipv4_t            ipv4;
    cpu_metadata_t    cpu_metadata;
    //icmp_t            icmp;
}

struct metadata {
    ipv4Addr_t nexthop;
}

parser MyParser(packet_in pkt,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        pkt.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        //transition select(hdr.ipv4.protocol) {
        //    TYPE_ICMP: parse_icmp;
        //    default: accept;
        //}
        transition accept;
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }
    
    //state parse_icmp {
    //    pkt.extract(hdr.icmp);
    //    transition accept;
    //}

}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    // Verify checksum
    // Data plane requirement 5.1: verify that the existing checksum and TTL are valid
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.tos,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    // Counter at Ingress
    // Data plane requirement 6: Provide counters for the following:
    counter(MAX_PORTS, CounterType.packets_and_bytes) ingressCounter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) ipIngressCounter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) arpIngressCounter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) ctrlPlaneCounter;

    action drop() {
        mark_to_drop();
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }
    // Data plane requirement 2: Use the routing table to perform a longest prefix match on destination IP addresses and return the appropriate egress port and next-hop address (or 0.0.0.0 for a directly attached destination).
    // Data plane requirement 5.2: look up the next-hop port and IP address in the route table
    // Data plane requirement 5.5: decrement TTL
    // Data plane requirement 5.7: transmit the new packet via the appropriate egress port
    action ipv4_forward(port_t port, ipv4Addr_t nexthop) {
        standard_metadata.egress_spec = port;
        meta.nexthop = nexthop;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.ingressPort = standard_metadata.ingress_port;
        if (standard_metadata.egress_spec != CPU_PORT) {
            hdr.cpu_metadata.egressPort = standard_metadata.egress_spec;
        }
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }
    // Data plane requirement 5.8: local IP packets (destined for the router) should be sent to the software
    action send_to_cpu(bit<12> padding) {
        cpu_meta_encap();
        hdr.cpu_metadata.padding = padding;
        standard_metadata.egress_spec = CPU_PORT;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_from_cpu() {
        cpu_meta_decap();
        if (hdr.cpu_metadata.multiCast == 0x1) {
            standard_metadata.mcast_grp = (bit<16>)hdr.cpu_metadata.egressPort;
        } else {
            standard_metadata.egress_spec = (port_t) hdr.cpu_metadata.egressPort;
        }
    }
    // Data plane requirement 5.3: look up the MAC address of the next-hop in the ARP table
    // ARP table lookup
    action update_dst_mac(macAddr_t dstEth) {
        hdr.ethernet.dstAddr = dstEth;
    }

    action update_src_mac(macAddr_t srcEth) {
        hdr.ethernet.srcAddr = srcEth;
    }

    // Data plane requirement 1: Provide a routing table that can store IP address/prefix pairs with their associated port and next-hop IP address.
    table routing_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    table local_mac_table {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            update_src_mac;
            drop;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    // Data plane requirement 3: Provide an ARP table that can store at least 64 entries. This will accept an IP address as a search key and will return the associated MAC address (if found). This table is modified by the software, which runs its own ARP protocol.
    table arp_table {
        key = {
            meta.nexthop: exact;
        }
        actions = {
            update_dst_mac;
            drop;
            send_to_cpu;
            NoAction;
        }
        size = 64;
        default_action = send_to_cpu((bit<12>)0x03);
//        default_action = NoAction;
    }
    // Data plane requirement 4: Provide a “local IP address table”. This will accept an IP address as a search key and will return a signal that indicates whether the correspond address was found. This table is used to identify IP addresses that should be forwarded to the CPU.
    table local_ip_table {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            send_to_cpu;
            drop;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    apply {
        ingressCounter.count((bit<32>) standard_metadata.ingress_port);
        if (hdr.cpu_metadata.isValid() && standard_metadata.ingress_port == CPU_PORT) {
            if (hdr.cpu_metadata.egressPort != 0) {
                send_from_cpu();
            }
            return;
        } else if (hdr.arp.isValid()) {
            arpIngressCounter.count((bit<32>) standard_metadata.ingress_port);
            ctrlPlaneCounter.count((bit<32>) standard_metadata.ingress_port);
            send_to_cpu((bit<12>)0x01);
            return;
        } 
        else if (hdr.ipv4.isValid()) {
            meta.nexthop = 0;
            ipIngressCounter.count((bit<32>) standard_metadata.ingress_port);
            local_ip_table.apply();
            if (hdr.cpu_metadata.isValid()) {
                return;
            }
            if (hdr.ipv4.ttl == 0) {
                drop();
            }
            routing_table.apply();
            if (meta.nexthop == 0) {
                meta.nexthop = hdr.ipv4.dstAddr;
            }
            if (hdr.ipv4.protocol == TYPE_PWOSPF) {
                ctrlPlaneCounter.count((bit<32>) standard_metadata.ingress_port);
                send_to_cpu((bit<12>)0x07);
                return;
            }

            arp_table.apply();
            local_mac_table.apply();

            //if (hdr.icmp.isValid() && hdr.icmp.type == ICMP_TYPE_ECHO) {
            //if (hdr.icmp.isValid()) {
            //    send_to_cpu((bit<12>)hdr.icmp.checksum);
            //    return;
            //}
            return;
        }
        // Data plane requirement 5.9: PWOSPF packets should be sent to the software
        // Data plane requirement 5.10: packets for which no matching entry is found in the routing table should be sent to the software
        // Data plane requirement 5.11: any packets that the hardware cannot deal with should be forwarded to the CPU. (e.g. not Version 4 IP)
        ctrlPlaneCounter.count((bit<32>) standard_metadata.ingress_port);
        send_to_cpu((bit<12>)0x02);
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    // Counter for Egress
    counter(MAX_PORTS, CounterType.packets_and_bytes) egressCounter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) ipEgressCounter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) arpEgressCounter;

    apply {
        egressCounter.count((bit<32>) standard_metadata.ingress_port);
        if (hdr.arp.isValid()) {
            arpEgressCounter.count((bit<32>) standard_metadata.ingress_port);
        } else if (hdr.ipv4.isValid()) {
            ipEgressCounter.count((bit<32>) standard_metadata.ingress_port);
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    // Data plane requirement 5.6: calculate a new IP checksum
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.tos,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyDeparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.cpu_metadata);
        pkt.emit(hdr.arp);
        pkt.emit(hdr.ipv4);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
