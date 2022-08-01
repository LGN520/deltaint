import operator
import glob
import struct
import time
import zlib
import multiprocessing
import sys
import socket
import os
import numpy as np
import random
import mmh3

exp_name=sys.argv[1]

height = 1
memory = 1024 * 1024 # 1MB
width = int(memory / height / 8)

def hash(flowkey):
    global width
    flowkey_bytes = struct.pack("L", flowkey)
    r = mmh3.hash(flowkey_bytes, signed=False)
    return r % width

def PINT_bits(hopnum):
    #total_bits = 0
    #prev_bits = 0
    #for i in range(hopnum):
    #    prev_bits += 8
    #    total_bits += prev_bits
    #return total_bits / hopnum
    return 8

def DINT_bits(hopnum, isfirst):
    total_bits = 0
    prev_bits = 0
    for i in range(hopnum):
        if i == 0:
            if isfirst:
                prev_bits += 9
            else:
                prev_bits += 1
        else:
            if isfirst:
                prev_bits += 8
            else:
                prev_bits += 0
        total_bits += prev_bits
    return total_bits / hopnum

sketch = []
for _ in range(height):
    sketch.append([0]*width)

packet_count_list = []
DINT_totalbits_list = []
PINT_totalbits_list = []
for hopnum in range(2, int(exp_name)+1):
    packet_count = 0
    PINT_totalbits = 0
    DINT_totalbits = 0
    f=open("experiments/"+exp_name+"/"+str(hopnum)+"/255_1000000","r")
    print(f)
    for line in f:
        packet_count = packet_count+1
        data=line.strip().split(",")
        data=[int(x) for x in data]
        total_packets=data[0]
        ttl=data[1]
        pkt_id=int(data[2])
        asm_hash=int(data[3])
        digest=int(data[4])
        actual_switch_id=int(data[5])
        src_ip = int(data[6])
        dst_ip = int(data[7])
        
        flowkey = src_ip << 32 | dst_ip
        for row in range(height):
            hash_idx = hash(flowkey)
            if sketch[row][hash_idx] == flowkey:
                isfirst = False
            else:
                isfirst = True
                sketch[row][hash_idx] = flowkey
        DINT_totalbits += DINT_bits(hopnum, isfirst)
        PINT_totalbits += PINT_bits(hopnum)

    print("Average bit [hopnum={}]: DINT {} PINT {}".format(hopnum, \
            DINT_totalbits/float(packet_count), PINT_totalbits/float(packet_count)))
    packet_count_list.append(packet_count)
    PINT_totalbits_list.append(PINT_totalbits)
    DINT_totalbits_list.append(DINT_totalbits)

PINT_avgbits_list = []
DINT_avgbits_list = []
for i in range(len(packet_count_list)):
    PINT_avgbits_list.append(PINT_totalbits_list[i]/float(packet_count_list[i]))
    DINT_avgbits_list.append(DINT_totalbits_list[i]/float(packet_count_list[i]))
print(PINT_avgbits_list)
print(DINT_avgbits_list)

packet_count_sum = sum(packet_count_list)
PINT_totalbits_sum = sum(PINT_totalbits_list)
DINT_totalbits_sum = sum(DINT_totalbits_list)
print("Average bit [in total]: DINT {} PINT {}".format(\
        DINT_totalbits_sum/float(packet_count_sum), PINT_totalbits_sum/float(packet_count_sum)))
