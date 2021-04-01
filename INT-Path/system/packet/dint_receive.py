import socket
# import parse
import dint_parse
# import processor
import redis
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
        r = redis.Redis(unix_socket_path='/var/run/redis/redis.sock')
        ownip = get_if_addr("eth0")
        ownmac = get_if_hwaddr("eth0")
        parse1 = dint_parse.parse()

        INTPATH_BW = 0 # INT-Path bandwidth usage
        DINT_BW = 0 # DeltaINT bandwidth usage
        INT_PACKET_NUM = 0 # Same for both INT-Path and DINT
        curdir = os.path.dirname(os.path.abspath(__file__))
        fd = open("{}/tmp/h{}_BW.txt".format(curdir, sys.argv[1]), "w+")
        deviceno_map = {}
        iport_map = {}
        eport_map = {}
        timedelta_map = {}
        ToR_deviceno, ToR_eport, ToR_timedelta = None, None, None # Though the link between ToR and host is overlapping, it is consistent for this application

        latency_threshold = int(receive_config["latency_threshold"])*1000 # 100000us = 100ms
        aging_time = int(receive_config["aging_time"])*1000 # 3000ms
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
                intpath_prevbw = 0
                dint_prevbw = 0
                #srcip, srcmac, intlist = rs
                srcip, srcmac, intlist, flowkey = rs

                # Convert each element in port_list into str
                for i in range(len(intlist)):
                    tmpkey = struct.pack("%dsB"%len(flowkey), flowkey, i)
                    # Device number
                    if intlist[i][0] is None:
                        if i == 0:
                            intlist[i][0] = ToR_deviceno
                            dint_prevbw += 1
                        else: 
                            if tmpkey not in deviceno_map.keys():
                                print("ERROR: non existent key {} in deviceno map".format(tmpkey), flush=True)
                                exit(-1)
                            else:
                                intlist[i][0] = deviceno_map[tmpkey]
                                dint_prevbw += 1
                    else:
                        if i == 0 and ToR_deviceno is None: # The first INT-Header corresponds to the last hop
                            ToR_deviceno = intlist[i][0]
                        deviceno_map[tmpkey] = intlist[i][0]
                        dint_prevbw += 9
                    # Ingress port
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
                    # Egress port
                    if intlist[i][2] is None:
                        if i == 0:
                            intlist[i][2] = ToR_eport
                            dint_prevbw += 1
                        else:
                            if tmpkey not in eport_map.keys():
                                print("ERROR: non existent key {} in eport map".format(tmpkey), flush=True)
                                exit(-1)
                            else:
                                intlist[i][2] = eport_map[tmpkey]
                                dint_prevbw += 1
                    else:
                        if i == 0 and ToR_eport is None:
                            ToR_eport = intlist[i][2]
                        eport_map[tmpkey] = intlist[i][2]
                        dint_prevbw += 9
                    # Latency
                    if intlist[i][3] is None:
                        if i == 0:
                            intlist[i][3] = ToR_timedelta
                        else:
                            if tmpkey not in timedelta_map.keys():
                                print("ERROR: non existent key {} in timedelta map".format(tmpkey), flush=True)
                            else:
                                intlist[i][3] = timedelta_map[tmpkey]
                                dint_prevbw += 1
                    else:
                        if i == 0:
                            ToR_timedelta = intlist[i][3]
                        timedelta_map[tmpkey] = intlist[i][3]
                        dint_prevbw += 32
                    print("recovered INT data [{}]: deviceno {}, iport {}, eport {}, timedelta {}".format(i, intlist[i][0], intlist[i][1], intlist[i][2], intlist[i][3]))
                    linkdown_detection_list.append("s{}-{}-{}".format(intlist[i][0], intlist[i][1], intlist[i][2]))
                    if intlist[i][3] < latency_threshold:
                        grayfailure_detection_list.append("s{}-{}-ok".format(intlist[i][0], intlist[i][2]))
                    intpath_prevbw += (8+8+8+32)
                    INTPATH_BW += intpath_prevbw # bits of all links for this INT-packet
                    DINT_BW += dint_prevbw # bits of all links for this INT-packet
                    INT_PACKET_NUM += 1
                    fd.write("INTPATH_BW {} DINT_BW {} INT_PACKET_NUM {} TIME {}\n".format(INTPATH_BW, DINT_BW, INT_PACKET_NUM, time.time()))
                    fd.flush()

                # Set for linkdown detection
                fmt = [ownip, ownmac, srcip, srcmac] + linkdown_detection_list
                key = "+".join(fmt)
                value = 0
                #print("{}, {}".format(key, value))
                r.set(key,value)
                r.pexpire(key, aging_time)

                # Set for gray failure detection
                for i in range(len(grayfailure_detection_list)):
                    key = grayfailure_detection_list[i]
                    r.set(key, value)
                    r.pexpire(key, aging_time)

        fd.close()
        s.close()


if __name__ == "__main__":
    receive1 = receive()
    receive1.sniff()
