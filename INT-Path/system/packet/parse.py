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
                    return ipv4[10], ethernet[1], int_headers
        return None

    def int_process(self, pkt):
        pkt_len = len(pkt)
        #int_header_size = 22
        int_header_size = 7
        int_num = int(pkt_len / int_header_size)
        if pkt_len != int_num * int_header_size:
            print("[Error] invalid pkt_len %d which should be %d * %d" % (pkt_len, int_num, int_header_size))
            exit(-1)
        print("Int num: {}".format(int_num), flush=True)

        int_headers = []
        for i in range(int_num):
            if i < int_num-1:
                #tmp = struct.unpack("!%dB%ds" % (int_header_size, len(pkt)-int_header_size), pkt)
                #tmp_int_bytes = tmp[0:int_header_size]
                #pkt = tmp[int_header_size]
                tmp = struct.unpack("!BBBI%ds" % (len(pkt)-int_header_size), pkt)
                tmp_int_bytes = tmp[0:4]
                pkt = tmp[4]
            else:
                #tmp_int_bytes = struct.unpack("!%dB" % int_header_size, pkt)
                tmp_int_bytes = struct.unpack("!BBBI", pkt)
            device_no = tmp_int_bytes[0] # 8-bit device_no
            ingress_port = tmp_int_bytes[1] # 8-bit ingress port
            egress_port = tmp_int_bytes[2] # 8-bit egress port
            deq_timedelta = tmp_int_bytes[3] # 32-bit timedelta
            #ingress_port = (tmp_int_bytes[1] << 1) | ((tmp_int_bytes[2] >> 7) & 0x1) # 9-bit ingress_port
            #egress_port = ((tmp_int_bytes[2] & 0x7f) << 2) | ((tmp_int_bytes[3] >> 6) & 0x3) # 9-bit egress_port
            #ingress_global_timestamp = ((tmp_int_bytes[3] & 0x3f) << 42) | (tmp_int_bytes[4] << 34) | (tmp_int_bytes[5] << 26) | (tmp_int_bytes[6] << 18) | \
            #        (tmp_int_bytes[7] << 10) | (tmp_int_bytes[8] << 2) | ((tmp_int_bytes[9] >> 6) & 0x3) # 48-bit ingress_global_timestamp
            #enq_timestamp = ((tmp_int_bytes[9] & 0x3f) << 26) | (tmp_int_bytes[10] << 18) | (tmp_int_bytes[11] << 10) | \
            #        (tmp_int_bytes[12] << 2) | ((tmp_int_bytes[13] >> 6) & 0x3) # 32-bit enq_timestamp
            #enq_qdepth = ((tmp_int_bytes[13] & 0x3f) << 13) | (tmp_int_bytes[14] << 5) | ((tmp_int_bytes[15] >> 3) & 0x1f) # 19-bit enq_qdepth
            #deq_timedelta = ((tmp_int_bytes[15] & 0x7) << 29) | (tmp_int_bytes[16] << 21) | (tmp_int_bytes[17] << 13) | \
            #        (tmp_int_bytes[18] << 5) | ((tmp_int_bytes[19] >> 3) & 0x1f) # 32-bit deq_timedelta
            #deq_qdepth = ((tmp_int_bytes[19] & 0x7) << 16) | (tmp_int_bytes[20] << 8) | tmp_int_bytes[21] # 19-bit deq_qdepth
            print("INT data [{}]:".format(i))
            #print([device_no, ingress_port, egress_port, ingress_global_timestamp, enq_timestamp, enq_qdepth, deq_timedelta, deq_qdepth], flush=True)
            print([device_no, ingress_port, egress_port, deq_timedelta], flush=True)
            int_headers.append((device_no, ingress_port, egress_port, deq_timedelta))
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

    def parse_udp(self, pkt):
        udp = struct.unpack("!4H", pkt)
        src_port = udp[0]
        dst_port = udp[1]
        length = udp[2]
        checksum = udp[3]
        return src_port, dst_port, length, checksum



if __name__ == "__main__":
    pass
