import socket
# import parse
import dint_parse
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
        parse1 = dint_parse.parse()

        INTPATH_BW = 0 # INT-Path bandwidth usage
        DINT_BW = 0 # DeltaINT bandwidth usage
        curdir = os.path.dirname(os.path.abspath(__file__))
        fd = open("{}/tmp/h{}_BW.txt".format(curdir, sys.argv[1]), "w")
        deviceno_map = {}
        iport_map = {}
        eport_map = {}
        while True:
            data = s.recv(2048)
            if not data:
                print("Client has exist")
                break
            # rs = parse1.filter(data) # srcip, srcmac, list of (deviceno, iport, eport) returned by parse.py
            rs = parse1.filter(data) # srcip, srcmac, list of (deviceno, iport, eport), 5-tuple flowkey returned by parse.py
            if rs != None:
                intpath_prevbw = 0
                dint_prevbw = 0
                #srcip, srcmac, intlist = rs
                srcip, srcmac, intlist, flowkey = rs

                # Convert each element in port_list into str
                for i in range(len(intlist)):
                    tmpkey = struct.pack("%dsB"%len(flowkey), flowkey, i)
                    if intlist[i][0] is None:
                        if tmpkey not in deviceno_map.keys():
                            print("ERROR: non existent key {} in deviceno map".format(tmpkey), flush=True)
                            exit(-1)
                        else:
                            intlist[i][0] = deviceno_map[tmpkey]
                            dint_prevbw += 1
                    else:
                        deviceno_map[tmpkey] = intlist[i][0]
                        dint_prevbw += 9
                    if intlist[i][1] is None:
                        if tmpkey not in iport_map.keys():
                            print("ERROR: non existent key {} in iport map".format(tmpkey), flush=True)
                            exit(-1)
                        else:
                            intlist[i][1] = iport_map[tmpkey]
                            dint_prevbw += 1
                    else:
                        iport_map[tmpkey] = intlist[i][1]
                        dint_prevbw += 9
                    if intlist[i][2] is None:
                        if tmpkey not in eport_map.keys():
                            print("ERROR: non existent key {} in eport map".format(tmpkey), flush=True)
                            exit(-1)
                        else:
                            intlist[i][2] = eport_map[tmpkey]
                            dint_prevbw += 1
                    else:
                        eport_map[tmpkey] = intlist[i][2]
                        dint_prevbw += 9
                    intlist[i] = "s{}-{}-{}".format(intlist[i][0], intlist[i][1], intlist[i][2])
                    intpath_prevbw += (8+8+8)
                    INTPATH_BW += intpath_prevbw # bits of all links for this INT-packet
                    DINT_BW += dint_prevbw # bits of all links for this INT-packet
                    fd.write("INTPATH_BW {} DINT_BW {} TIME {}\n".format(INTPATH_BW, DINT_BW, time.time()))
                    fd.flush()
                fmt = [ownip, ownmac, srcip, srcmac] + intlist
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
