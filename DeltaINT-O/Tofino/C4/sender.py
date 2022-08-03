#!/usr/bin/env python

# Execute on h1

from scapy.fields import IPField, BitField, ByteField, ShortField, ByteEnumField, \
        IntField, ShortEnumField, StrField, XByteField, XShortField
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers
from scapy.all import *

from time import sleep

ETHERTYPE_IPV4 = 0x0800
PROTOTYPE_TCP = 0x06
PROTOTYPE_UDP = 0x11

src_mac = "3c:fd:fe:bb:ca:79"
src_ip = "10.0.1.11"
src_port = 1111
src_if = "enp129s0f1"

dst_mac = "3c:fd:fe:bb:c9:c8"
dst_ip = "10.0.1.13"
dst_port = 1234
dst_if = "enp129s0f0"

def main():
    print("Send custom packet to query...")
    pkt = Ether(src=src_mac, dst=dst_mac, type=ETHERTYPE_IPV4) / \
            IP(src=src_ip, dst=dst_ip, ttl=64, proto=PROTOTYPE_UDP, len=28) / \
            UDP(sport=src_port, dport=dst_port, len=8)
    #pkt.show()

    sendp(pkt, iface=src_if, verbose=0)

if __name__ == "__main__":
    main()

