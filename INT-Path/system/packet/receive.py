import socket
import parse
# import processor
import redis
import sys
import time
import os

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

        INTPATH_BW = 0 # Bandwidth usage
        curdir = os.path.dirname(os.path.abspath(__file__))
        fd = open("{}/tmp/h{}_INTPATH_BW.txt".format(curdir, sys.argv[1]), "w")
        while True:
            data = s.recv(2048)
            if not data:
                print("Client has exist")
                break
            rs = parse1.filter(data) # srcip, srcmac, list of (deviceno, iport, eport)
            if rs != None:
                # Convert each element in port_list into str
                for i in range(len(rs[2])):
                    rs[2][i] = "s{}-{}-{}".format(rs[2][i][0], rs[2][i][1], rs[2][i][2])
                    INTPATH_BW += (i+1) * (8+9+9) # bits of all links
                    fd.write("INTPATH_BW {} TIME {}\n".format(INTPATH_BW, time.time()))
                    fd.flush()
                fmt = [ownip, ownmac, rs[0], rs[1]] + rs[2]
                key = "+".join(fmt)
                value = 0
                print("{}, {}".format(key, value))
                r.set(key,value)
                r.pexpire(key,3000)
        fd.close()
        s.close()


if __name__ == "__main__":
    receive1 = receive()
    receive1.sniff()
