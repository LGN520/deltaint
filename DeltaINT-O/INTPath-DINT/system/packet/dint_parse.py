import struct
import socket
import redis
import sys

from scapy.all import get_if_hwaddr

class parse():

    def filter(self, pkt_raw):
        pkt_len = len(pkt_raw)
        # !: Network (Big-endian), 14s: 14-byte string, pkt_len-14 char
        pkt = struct.unpack("!14s%ds" % (pkt_len-14), pkt_raw)
        ethernet = self.parse_ethernet(pkt[0])
        ownmac = get_if_hwaddr("eth0")
        if ethernet[2] == 0x0800 and ethernet[1] != ownmac: # ipv4 and not TX packet
            pkt = struct.unpack("!20s%ds" % (len(pkt[1])-20), pkt[1])
            ipv4 = self.parse_ipv4(pkt[0])
            if ipv4[8] == 0x11: # udp
                pkt = struct.unpack("!8s%ds" % (len(pkt[1])-8), pkt[1])
                udp = self.parse_udp(pkt[0])
                if udp[1] == 2222: # INT-packet
                    print("dst mac: %s, src mac: %s" % (ethernet[0], ethernet[1]), flush=True)
                    print("src ip: %s, dst ip: %s" % (ipv4[10], ipv4[11]), flush=True)
                    print("src port: %s, dst port: %s" % (udp[0], udp[1]), flush=True)
                    print("udp len: {}, remaining bytes: {}".format(udp[2], len(pkt[1])), flush=True)
                    pkt = struct.unpack("!64s%dsI" % (len(pkt[1])-64-4), pkt[1]) # 512-bit source routing, int metadata, 32-bit actId
                    print("source route: {}, act id: {}".format(pkt[0], pkt[2]), flush=True)
                    int_headers = self.int_process(pkt[1])
                    flowkey = struct.pack("4s4sHHB", self.ipv4_addrstr_to_bytes(ipv4[10]), self.ipv4_addrstr_to_bytes(ipv4[11]), udp[0], udp[1], ipv4[8])
                    return ipv4[10], ethernet[1], int_headers, flowkey
        return None

    def int_process(self, pkt):
        int_num = 0
        int_headers = []
        i = 0
        while len(pkt) >= 1:
            # Read int bitmap
            meta_num = 0
            bitmap, pkt = struct.unpack("!B%ds" % (len(pkt)-1), pkt)
            device_bit = bitmap>>7 & 0x1
            if device_bit == 1:
                meta_num += 1
            iport_bit = bitmap>>6 & 0x1
            if iport_bit == 1:
                meta_num += 1
            eport_bit = bitmap>>5 & 0x1
            if eport_bit == 1:
                meta_num += 1
            timedelta_bit = bitmap>>4 & 0x1
            if timedelta_bit == 1:
                meta_num += 1
            print("bitmap {} device bit {} iport bit {} eport bit {} timedelta bit {}".format(bitmap, device_bit, iport_bit, eport_bit, timedelta_bit), flush=True)
            if len(pkt) < meta_num*1:
                print("ERROR: pktlen {} < {}".format(len(pkt), meta_num*1), flush=True)
                exit(-1)

            # Read INT metadata
            device_no = None
            if device_bit == 1:
                device_no, pkt = struct.unpack("!B%ds" % (len(pkt)-1), pkt)
            ingress_port = None
            if iport_bit == 1:
                ingress_port, pkt = struct.unpack("!B%ds" % (len(pkt)-1), pkt)
            egress_port = None
            if eport_bit == 1:
                egress_port, pkt = struct.unpack("!B%ds" % (len(pkt)-1), pkt)
            timedelta = None
            if timedelta_bit == 1:
                timedelta, pkt = struct.unpack("!I%ds" % (len(pkt)-4), pkt)
                timedelta = timedelta * 128

            print("original INT data [{}]: deviceno {}, iport {}, eport {}, timedelta {}".format(i, device_no, ingress_port, egress_port, timedelta))
            int_headers.append([device_no, ingress_port, egress_port, timedelta])
            i += 1
        return int_headers

    # B: unsigned char 1B; H: unsigned short 2B; I: unsigned int 4B

    def parse_ethernet(self, pkt):
        ethernet = struct.unpack("!6B6BH", pkt)
        ethernet_str = []
        for i in range(12):
            temp = ethernet[i]
            temp = (hex(temp))[2:] # Skip "0x"
            if len(temp) == 1:
                temp = "0"+temp
            ethernet_str.append(temp)

        dstAddr = "%s:%s:%s:%s:%s:%s" % (
            ethernet_str[0], ethernet_str[1], ethernet_str[2], ethernet_str[3], ethernet_str[4], ethernet_str[5])  # 1
        srcAddr = "%s:%s:%s:%s:%s:%s" % (
            ethernet_str[6], ethernet_str[7], ethernet_str[8], ethernet_str[9], ethernet_str[10], ethernet_str[11])  # 2
        etherType = ethernet[12]  # 3
        return dstAddr, srcAddr, etherType

    def ethernet_addrstr_to_bytes(self, ethernet_addstr):
        temp = ethernet_str.split(":")
        for i in range(len(temp)):
            temp[i] = int(temp[i][0])*16+int(temp[i][1])
        rs = struct.pack("6B", temp[0], temp[1], temp[2], temp[3], temp[4], temp[5])
        return rs

    def parse_ipv4(self, pkt):
        ipv4 = struct.unpack("!BBHHHBBH4s4s", pkt)
        version = (ipv4[0] & 0xf0) >> 4  # 1
        ihl = ipv4[0] & 0x0f  # 2
        diffserv = ipv4[1]  # 3
        totalLen = ipv4[2]  # 4
        identification = ipv4[3]  # 5
        flags = (ipv4[4] & 0xe000) >> 13  # 6
        fragOffset = ipv4[4] & 0x1fff  # 7
        ttl = ipv4[5]  # 8
        protocol = ipv4[6]  # 9
        hdrChecksum = ipv4[7]  # 10
        srcAddr = ipv4[8]  # 11
        dstAddr = ipv4[9]  # 12
        srcAddr = socket.inet_ntoa(srcAddr)
        dstAddr = socket.inet_ntoa(dstAddr)
        return version, ihl, diffserv, totalLen, identification, flags, fragOffset, ttl, protocol, hdrChecksum, srcAddr, dstAddr

    def ipv4_addrstr_to_bytes(self, ipv4_addrstr):
        rs = socket.inet_aton(ipv4_addrstr)
        return rs

    def parse_udp(self, pkt):
        udp = struct.unpack("!4H", pkt)
        src_port = udp[0]
        dst_port = udp[1]
        length = udp[2]
        checksum = udp[3]
        return src_port, dst_port, length, checksum



if __name__ == "__main__":
    pass
