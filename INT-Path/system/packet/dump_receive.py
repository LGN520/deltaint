import socket
# import parse
import dump_parse
# import processor
# import redis
import sys
import time
import os
import struct
import json

from scapy.all import get_if_addr, get_if_list, get_if_hwaddr

#ifs = get_if_list()
#print(ifs, flush=True)

with open("../config.json", "r") as f:
    receive_config = json.load(f)

class receive():
    def sniff(self):
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                          socket.htons(0x0003))
        s.setsockopt(socket.SOL_SOCKET, 25, str("eth0" + '\0').encode('utf-8'))
        parse1 = dump_parse.parse()

        curdir = os.path.dirname(os.path.abspath(__file__))
        fd = open("{}/tmp/h{}_dump.txt".format(curdir, sys.argv[1]), "w+")

        while True:
            data = s.recv(2048)
            if not data:
                print("Client has exist")
                break
            rs = parse1.filter(data) # 2-tuple flowkey, list of (deviceno, iport, eport, timedelta)
            if rs != None:
                flowkey, intlist = rs
                flowkey = struct.unpack("L", flowkey)[0]
                intstr = ""
                for i in range(len(intlist)):
                    if i == 0:
                        intstr = "{} {} {} {}".format(intlist[i][0], intlist[i][1], intlist[i][2], intlist[i][3])
                    else:
                        intstr = "{} {} {} {} {}".format(intstr, intlist[i][0], intlist[i][1], intlist[i][2], intlist[i][3])
                fd.write("{} {}\n".format(flowkey, intstr))
                fd.flush()

        fd.close()
        s.close()


if __name__ == "__main__":
    receive1 = receive()
    receive1.sniff()
