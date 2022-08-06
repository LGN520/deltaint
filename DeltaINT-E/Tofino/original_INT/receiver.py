#!/usr/bin/env python

# Execute on h2

from scapy.fields import IPField, BitField, ByteField, ShortField, ByteEnumField, \
        IntField, ShortEnumField, StrField, XByteField, XShortField
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers
from scapy.all import *

from time import sleep

import struct
import binascii

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

cnt = 0

def dumpBytes(bytesdata):
    msg = binascii.hexlify(bytearray(bytesdata))
    print(msg)

def handlePacket(packet):
    global cnt
    cnt = cnt + 1
    print("\nIndex of the packet: {}".format(cnt))

    if packet[Ether].type == ETHERTYPE_IPV4 and packet[IP].proto == PROTOTYPE_UDP and packet[UDP].dport == dst_port:
        #packet.show()
        
        payload_buf = bytes(packet[Raw].load)
        #dumpBytes(payload_buf)
        _, int_len, _, payload_buf = struct.unpack("!BHB{}s".format(len(payload_buf) - 4), payload_buf)
        print(int_len)
        power = struct.unpack("!B", payload_buf)
        print(power)
        #deviceid, iport, eport, latency = struct.unpack("!BBBI", payload_buf)
        #print(deviceid, iport, eport, latency)

def main():
    print("Sniff UDP packet to get result (listening)...")
    sniff(iface=dst_if, prn=lambda x: handlePacket(x), count=0)

if __name__ == "__main__":
    main()

