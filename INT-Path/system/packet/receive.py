import socket
import parse
# import processor
import redis
import sys
import time
import os
import struct

from scapy.all import get_if_addr, get_if_list, get_if_hwaddr

#ifs = get_if_list()
#print(ifs, flush=True)

class receive():
    def sniff(self):
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                          socket.htons(0x0003))
        s.setsockopt(socket.SOL_SOCKET, 25, str("eth0" + '\0').encode('utf-8'))
        r = redis.Redis(unix_socket_path='/var/run/redis/redis.sock')
        ownip = get_if_addr("eth0")
        ownmac = get_if_hwaddr("eth0")
        parse1 = parse.parse()

        latency_threshold = 100000 # 100000us = 100ms
        aging_time = 3000 # 3000ms
        while True:
            linkdown_detection_list = []
            grayfailure_detection_list = []
            data = s.recv(2048)
            if not data:
                print("Client has exist")
                break
            # rs = parse1.filter(data) # srcip, srcmac, list of (deviceno, iport, eport) returned by parse.py
            rs = parse1.filter(data) # srcip, srcmac, list of (deviceno, iport, eport, timedelta), 5-tuple flowkey returned by parse.py
            if rs != None:
                srcip, srcmac, intlist = rs

                # Convert each element in port_list into str
                for i in range(len(intlist)):
                    linkdown_detection_list.append("s{}-{}-{}".format(intlist[i][0], intlist[i][1], intlist[i][2]))
                    if intlist[i][3] < latency_threshold:
                        grayfailure_detection_list.append("s{}-{}-ok".format(intlist[i][0], intlist[i][2]))

                # Set for linkdown detection
                fmt = [ownip, ownmac, srcip, srcmac] + linkdown_detection_list
                key = "+".join(fmt)
                value = 0
                print("{}, {}".format(key, value))
                r.set(key,value)
                r.pexpire(key, aging_time)

                # Set for gray failure detection
                for i in range(len(grayfailure_detection_list)):
                    key = grayfailure_detection_list[i]
                    r.set(key, value)
                    r.pexpire(key, aging_time)

        s.close()


if __name__ == "__main__":
    receive1 = receive()
    receive1.sniff()
