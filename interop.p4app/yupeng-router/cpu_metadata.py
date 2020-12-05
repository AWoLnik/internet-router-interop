from scapy.fields import BitField, ShortField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP

TYPE_CPU_METADATA = 0x080a

class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [ BitField("fromCpu", 0, 1),
                    BitField("multiCast", 0, 1),
                    BitField("padding", 0, 12),
                    BitField("ingressPort", 0, 9),
                    BitField("egressPort", None, 9),
                    ShortField("origEtherType", None)]

bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEtherType=0x0800)
bind_layers(CPUMetadata, ARP, origEtherType=0x0806)
