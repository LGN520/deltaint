import math
import time
import sys
import numpy as np
import operator
import random
import os
import mmh3
import struct

# Sketch
totalbytes = 1024 * 1024 # 1MB
hashnum = 1
width = int(totalbytes / (8 + 4) / hashnum)
def init_sketch():
    sketch = [] # [[(flowkey, latency)*width]*hashnum]
    for i in range(hashnum):
        sketch.append([])
        for j in range(width):
            sketch[i].append([-1, -1])
    return sketch
pernode_sketch_map = {} # {node, sketch}
def hash(flowkey):
    global width
    flowkey_bytes = struct.pack("L", flowkey)
    r = mmh3.hash(flowkey_bytes, signed=False)
    return r % width
def state_load(sketch, flowkey):
    global hashnum
    for row in range(hashnum):
        col = hash(flowkey)
        bucket = sketch[row][col]
        if bucket[0] == flowkey:
            return bucket[1]
    return None
def state_update(sketch, flowkey, latency):
    global hashnum
    for row in range(hashnum):
        col = hash(flowkey)
        bucket = sketch[row][col]
        bucket[0] = flowkey
        bucket[1] = latency

# Bandwidth cost
int_perpkt_bwcost_map = {} # {flow, {seq, [[bwcost*hopnum]*runtimes]}}
dinto_perpkt_bwcost_map = {} # {flow, {seq, [[bwcost*hopnum]*runtimes]}}
dinte_perpkt_bwcost_map = {} # {flow, {seq, [[bwcost*hopnum]*runtimes]}}
complete_bitcost = 32 # original INT
#delta_threshold = 1
#delta_threshold = 2
#delta_threshold = 4
#delta_threshold = 8
#delta_threshold = 16
#delta_threshold = 64
#delta_threshold = 256
delta_threshold = 1024
dint_complete_bitcost = 1 + complete_bitcost
dinto_delta_bitcost = 1
if delta_threshold == 1:
    dinte_nonzero_delta_bitcost, dinte_zero_delta_bitcost = 1+2, 1+1
elif delta_threshold == 2:
    dinte_nonzero_delta_bitcost, dinte_zero_delta_bitcost = 1+3, 1+1
elif delta_threshold == 4:
    dinte_nonzero_delta_bitcost, dinte_zero_delta_bitcost = 1+4, 1+1
elif delta_threshold == 8:
    dinte_nonzero_delta_bitcost, dinte_zero_delta_bitcost = 1+5, 1+1
elif delta_threshold == 16:
    dinte_nonzero_delta_bitcost, dinte_zero_delta_bitcost = 1+6, 1+1
elif delta_threshold == 64:
    dinte_nonzero_delta_bitcost, dinte_zero_delta_bitcost = 1+8, 1+1
elif delta_threshold == 256:
    dinte_nonzero_delta_bitcost, dinte_zero_delta_bitcost = 1+10, 1+1
elif delta_threshold == 1024:
    dinte_nonzero_delta_bitcost, dinte_zero_delta_bitcost = 1+12, 1+1

# Measurement accuracy
truth = []
origin_int = []
dinto = []
dinte = []
def get_re(truth, estimation):
    if truth != 0:
        re = float(abs(estimation-truth)) / float(truth)
    else:
        if estimation == 0:
            re = 0
        else:
            re = 1
    return re

### Trace replay ###

f=open("experiments/delays/processed_data","r")
for line in f:
    digests=line.strip().split(" ")
    flow = int(digests[0])
    seq = digests[1]
    node = digests[2]
    hopidx = int(digests[3])
    latency = int(digests[4])
    hopnum = int(digests[5]) # unused

    truth.append(latency)

    # INT
    origin_int.append(latency)
    if flow not in int_perpkt_bwcost_map:
        int_perpkt_bwcost_map[flow] = {}
    if seq not in int_perpkt_bwcost_map[flow]:
        int_perpkt_bwcost_map[flow][seq] = []
    if hopidx == 0:
        int_perpkt_bwcost_map[flow][seq].append([complete_bitcost])
    else:
        tmp_int_prevbw = int_perpkt_bwcost_map[flow][seq][-1][-1]
        int_perpkt_bwcost_map[flow][seq][-1].append(tmp_int_prevbw + complete_bitcost)

    # DINTO/E
    if node not in pernode_sketch_map:
        pernode_sketch_map[node] = init_sketch()
    embedded_latency = state_load(pernode_sketch_map[node], flow)
    if flow not in dinto_perpkt_bwcost_map:
        dinto_perpkt_bwcost_map[flow]  = {}
    if seq not in dinto_perpkt_bwcost_map[flow]:
        dinto_perpkt_bwcost_map[flow][seq] = []
    if flow not in dinte_perpkt_bwcost_map:
        dinte_perpkt_bwcost_map[flow]  = {}
    if seq not in dinte_perpkt_bwcost_map[flow]:
        dinte_perpkt_bwcost_map[flow][seq] = []
    if ((embedded_latency is None) or (abs(latency - embedded_latency) > delta_threshold)):
        state_update(pernode_sketch_map[node], flow, latency)
        # DINTO
        dinto.append(latency)
        if hopidx == 0:
            dinto_perpkt_bwcost_map[flow][seq].append([dint_complete_bitcost])
        else:
            tmp_dinto_prevbw = dinto_perpkt_bwcost_map[flow][seq][-1][-1]
            dinto_perpkt_bwcost_map[flow][seq][-1].append(tmp_dinto_prevbw + dint_complete_bitcost)
        # DINTE
        dinte.append(latency)
        if hopidx == 0:
            dinte_perpkt_bwcost_map[flow][seq].append([dint_complete_bitcost])
        else:
            tmp_dinte_prevbw = dinte_perpkt_bwcost_map[flow][seq][-1][-1]
            dinte_perpkt_bwcost_map[flow][seq][-1].append(tmp_dinte_prevbw + dint_complete_bitcost)
    else:
        # DINTO
        dinto.append(embedded_latency)
        if hopidx == 0:
            dinto_perpkt_bwcost_map[flow][seq].append([dinto_delta_bitcost])
        else:
            tmp_dinto_prevbw = dinto_perpkt_bwcost_map[flow][seq][-1][-1]
            dinto_perpkt_bwcost_map[flow][seq][-1].append(tmp_dinto_prevbw + dinto_delta_bitcost)
        # DINTE
        dinte.append(latency)
        if abs(latency - embedded_latency) == 0:
            if hopidx == 0:
                dinte_perpkt_bwcost_map[flow][seq].append([dinte_zero_delta_bitcost])
            else:
                tmp_dinte_prevbw = dinte_perpkt_bwcost_map[flow][seq][-1][-1]
                dinte_perpkt_bwcost_map[flow][seq][-1].append(tmp_dinte_prevbw + dinte_zero_delta_bitcost)
        else:
            if hopidx == 0:
                dinte_perpkt_bwcost_map[flow][seq].append([dinte_nonzero_delta_bitcost])
            else:
                tmp_dinte_prevbw = dinte_perpkt_bwcost_map[flow][seq][-1][-1]
                dinte_perpkt_bwcost_map[flow][seq][-1].append(tmp_dinte_prevbw + dinte_nonzero_delta_bitcost)
f.close()

### Bandwidth cost ###

sum_int_avgbitcost, sum_dinto_avgbitcost, sum_dinte_avgbitcost = 0, 0, 0

# Original INT
pktnum = 0
for flow, seq_bwcost_map in int_perpkt_bwcost_map.items():
    for seq, runtimes_bwcost_list in seq_bwcost_map.items():
        for hop_bwcost_list in runtimes_bwcost_list:
            pktnum += 1
            tmp_hopnum = len(hop_bwcost_list)
            tmp_bitcost = 0
            for i in range(len(hop_bwcost_list)):
                tmp_bitcost += hop_bwcost_list[i]
            sum_int_avgbitcost += (float(tmp_bitcost) / float(tmp_hopnum))
int_avgbitcost = float(sum_int_avgbitcost) / float(pktnum)

# DeltaINT-O
pktnum = 0
for flow, seq_bwcost_map in dinto_perpkt_bwcost_map.items():
    for seq, runtimes_bwcost_list in seq_bwcost_map.items():
        for hop_bwcost_list in runtimes_bwcost_list:
            pktnum += 1
            tmp_hopnum = len(hop_bwcost_list)
            tmp_bitcost = 0
            for i in range(len(hop_bwcost_list)):
                tmp_bitcost += hop_bwcost_list[i]
            sum_dinto_avgbitcost += (float(tmp_bitcost) / float(tmp_hopnum))
dinto_avgbitcost = float(sum_dinto_avgbitcost) / float(pktnum)

# DeltaINT-E
pktnum = 0
for flow, seq_bwcost_map in dinte_perpkt_bwcost_map.items():
    for seq, runtimes_bwcost_list in seq_bwcost_map.items():
        for hop_bwcost_list in runtimes_bwcost_list:
            pktnum += 1
            tmp_hopnum = len(hop_bwcost_list)
            tmp_bitcost = 0
            for i in range(len(hop_bwcost_list)):
                tmp_bitcost += hop_bwcost_list[i]
            sum_dinte_avgbitcost += (float(tmp_bitcost) / float(tmp_hopnum))
dinte_avgbitcost = float(sum_dinte_avgbitcost) / float(pktnum)

print("[Average bit cost] original INT: {}, DeltaINT-O: {}, DeltaINT-E: {}".format(int_avgbitcost, dinto_avgbitcost, dinte_avgbitcost))

int_res, dinto_res, dinte_res = [], [], []
for i in range(len(truth)):
    int_re = get_re(truth[i], origin_int[i])
    int_res.append(int_re)
    dinto_re = get_re(truth[i], dinto[i])
    dinto_res.append(dinto_re)
    dinte_re = get_re(truth[i], dinte[i])
    dinte_res.append(dinte_re)
int_finalre = np.average(np.array(int_res))
dinto_finalre = np.average(np.array(dinto_res))
dinte_finalre = np.average(np.array(dinte_res))
print("[Relative error on collected INT states] original INT: {}, DeltaINT-O: {}, DeltaINT-E: {}".format(int_finalre, dinto_finalre, dinte_finalre))
