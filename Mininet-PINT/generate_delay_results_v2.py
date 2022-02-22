import math
import time
import sys
import numpy as np
import operator
import random
import os
import mmh3
import struct
from kll import KLL

random.seed(30)

def get_approx_res(perflow_pernode_approx, perflow_pernode_truth):
    sketch_size=500 # KLL sketch size
    # Using sketch to store digests
    kll = KLL(sketch_size)
    for tmp_flow in perflow_pernode_approx.keys():
        for tmp_node in perflow_pernode_approx[tmp_flow].keys():
            v = "{}-{}-{}".format(tmp_flow, tmp_node, perflow_pernode_approx[tmp_flow][tmp_node])
            kll.update(v) # v: flow-node-approx_value

    # Enumerate all elements in KLL sketch to get perflow pernode quantile latency
    tmp_perflow_pernode_estimation = {}
    for i in range(len(kll.compactors)):
        for j in range(len(kll.compactors[i]))
            v = kll.compactors[i][j]
            tmp_flow, tmp_node, tmp_approx_value = v.split("-")
            if tmp_flow not in tmp_perflow_pernode_estimation:
                tmp_perflow_pernode_estimation[tmp_flow] = {}
            if tmp_node not in tmp_perflow_pernode_estimation[tmp_flow]:
                tmp_perflow_pernode_estimation[tmp_flow][tmp_node] = []
            tmp_perflow_pernode_estimation[tmp_flow][tmp_node].append(tmp_approx_value)

    median_res = []
    tail_res = []
    for flow in perflow_pernode_truth.keys():
        for node in perflow_pernode_truth[flow].keys():
            truth_list = perflow_pernode_truth[flow][node]
            truth_median = np.median(truth_list)
            truth_tail = np.percentile(truth_list, 99)

            if flow not in tmp_perflow_pernode_estimation or node not in tmp_perflow_pernode_estimation[flow]:
                median_res.append(1.0)
                tail_res.append(1.0)
            else:
                estimation_list = tmp_perflow_pernode_estimation[flow][node]
                estimation_median = np.median(estimation_list)
                estimation_tail = np.percentile(estimation_list, 99)
                diff_median = abs(truth_median - estimation_median)
                diff_tail = abs(truth_tail - estimation_tail)
                if truth_median == 0:
                    median_res.append(0.0)
                    # Follow PINT
                    #if estimation_median == 0:
                    #    median_res.append(0.0)
                    #else:
                    #    median_res.append(1.0)
                else:
                    median_res.append(float(diff_median) / float(truth_median))
                if truth_tail == 0:
                    tail_res.append(0.0)
                    # Follow PINT
                    #if estimation_tail == 0:
                    #    tail_res.append(0.0)
                    #else:
                    #    tail_res.append(1.0)
                else:
                    tail_res.append(float(diff_tail) / float(truth_tail))

    median_avgre = sum(median_res) / float(len(median_res))
    tail_avgre = sum(tail_res) / float(len(tail_res))
    return median_avgre, tail_avgre

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

# Approximation
packets_range=[100, 500, 1000, 5000, 10000]
ap = 0.022 # We focus on 8 bits here
#all_approx=set() # Approximate coefficient
#approx_map={} # Approximate coefficiet -> bit number
#for bits in [4,8]:
#    if bits==4:
#        ap=0.42
#    if bits==8:
#        ap=0.022
#    all_approx.add(ap)
#    approx_map[ap]=bits

# Bandwidth cost
pint_perpkt_bwcost_map = {} # {flow, {seq, [[bwcost*hopnum]*runtimes]}}
dinto_perpkt_bwcost_map = {} # {flow, {seq, [[bwcost*hopnum]*runtimes]}}
dinte_perpkt_bwcost_map = {} # {flow, {seq, [[bwcost*hopnum]*runtimes]}}
complete_bitcost = 8 # original INT
#delta_threshold = 1
#delta_threshold = 2
#delta_threshold = 4
#delta_threshold = 8
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

# Latency measurement accuracy
pint_median_avgre_list, pint_tail_avgre_list = [], []
dinto_median_avgre_list, dinto_tail_avgre_list = [], []
dinte_median_avgre_list, dinte_tail_avgre_list = [], []

### Trace replay ###

for packets in packets_range:
    perflow_pernode_truth = {} # {flow, {node, [latency * pktnum]}}
    pint_perflow_pernode_approx = {} # {flow, node, [approx * pktnum]}
    dinto_perflow_pernode_approx = {} # {flow, node, [approx * pktnum]}
    dinte_perflow_pernode_approx = {} # {flow, node, [approx * pktnum]}
    eventnum = 0

    f=open("experiments/delays/processed_data","r")
    for line in f:
        digests=line.strip().split(" ")
        flow = int(digests[0])
        seq = digests[1]
        node = digests[2]
        hopidx = int(digests[3])
        latency = int(digests[4])
        hopnum = int(digests[5])

        if flow not in perflow_pernode_truth:
            perflow_pernode_truth[flow] = {}
        if node not in perflow_pernode_truth[flow]:
            perflow_pernode_truth[flow][node] = []
        # PINT
        if flow not in pint_perflow_pernode_approx:
            pint_perflow_pernode_approx[flow] = {}
        if node not in pint_perflow_pernode_approx[flow]:
            pint_perflow_pernode_approx[flow][node] = []
        if flow not in pint_perpkt_bwcost_map:
            pint_perpkt_bwcost_map[flow] = {}
        if seq not in pint_perpkt_bwcost_map[flow]:
            pint_perpkt_bwcost_map[flow][seq] = []
        # DINTO/E
        if node not in pernode_sketch_map:
            pernode_sketch_map[node] = init_sketch()
        # DINTO
        if flow not in dinto_perflow_pernode_approx:
            dinto_perflow_pernode_approx[flow] = {}
        if node not in dinto_perflow_pernode_approx[flow]:
            dinto_perflow_pernode_approx[flow][node] = []
        if flow not in dinto_perpkt_bwcost_map:
            dinto_perpkt_bwcost_map[flow]  = {}
        if seq not in dinto_perpkt_bwcost_map[flow]:
            dinto_perpkt_bwcost_map[flow][seq] = []
        # DINTE
        if flow not in dinte_perflow_pernode_approx:
            dinte_perflow_pernode_approx[flow] = {}
        if node not in dinte_perflow_pernode_approx[flow]:
            dinte_perflow_pernode_approx[flow][node] = []
        if flow not in dinte_perpkt_bwcost_map:
            dinte_perpkt_bwcost_map[flow]  = {}
        if seq not in dinte_perpkt_bwcost_map[flow]:
            dinte_perpkt_bwcost_map[flow][seq] = []

        perflow_pernode_truth[flow][node].append(latency)

        # Value approximation (follow PINT)
        approx_value = 0
        if latency != 0:
            range_1=int(math.log(latency, (1+ap)**2))
            range_2=int(math.log(latency, (1+ap)**2)+0.5)
            approx_value_1=(1+ap)**(2*range_1)
            approx_value_2=(1+ap)**(2*range_2)
            diff_1=latency-approx_value_1
            if diff_1<0:
                diff_1=-1*diff_1
            diff_2=latency-approx_value_2
            if diff_2<0:
                diff_2=-1*diff_2
            if diff_1 <= diff_2:
                approx_value = approx_value_1
            if diff_1 > diff_2:
                approx_value = approx_value_2

        # PINT
        if (random.randint(1, 2) == 1) or (hopidx==hopnum-1): # Sampling by global hashing for PINT
            pint_perflow_pernode_approx[flow][node].append(approx_value)
            if hopidx == 0:
                pint_perpkt_bwcost_map[flow][seq].append([complete_bitcost])
            else:
                tmp_pint_prevbw = pint_perpkt_bwcost_map[flow][seq][-1][-1]
                pint_perpkt_bwcost_map[flow][seq][-1].append(tmp_pint_prevbw + complete_bitcost)
        else:
            if hopidx == 0:
                pint_perpkt_bwcost_map[flow][seq].append([0])
            else:
                tmp_pint_prevbw = pint_perpkt_bwcost_map[flow][seq][-1][-1]
                pint_perpkt_bwcost_map[flow][seq][-1].append(tmp_pint_prevbw + 0)

        # DINTO/E
        embedded_approx_value = state_load(pernode_sketch_map[node], flow)
        if ((embedded_approx_value is None) or (abs(approx_value - embedded_latency) > delta_threshold)):
            state_update(pernode_sketch_map[node], flow, approx_value)
            # DINTO
            dinto_perflow_pernode_approx[flow][node].append(approx_value)
            if hopidx == 0:
                dinto_perpkt_bwcost_map[flow][seq].append([dint_complete_bitcost])
            else:
                tmp_dinto_prevbw = dinto_perpkt_bwcost_map[flow][seq][-1][-1]
                dinto_perpkt_bwcost_map[flow][seq][-1].append(tmp_dinto_prevbw + dint_complete_bitcost)
            # DINTE
            dinte_perflow_pernode_approx[flow][node].append(approx_value)
            if hopidx == 0:
                dinte_perpkt_bwcost_map[flow][seq].append([dint_complete_bitcost])
            else:
                tmp_dinte_prevbw = dinte_perpkt_bwcost_map[flow][seq][-1][-1]
                dinte_perpkt_bwcost_map[flow][seq][-1].append(tmp_dinte_prevbw + dint_complete_bitcost)
        else:
            # DINTO
            dinto_perflow_pernode_approx[flow][node].append(embedded_approx_value)
            if hopidx == 0:
                dinto_perpkt_bwcost_map[flow][seq].append([dinto_delta_bitcost])
            else:
                tmp_dinto_prevbw = dinto_perpkt_bwcost_map[flow][seq][-1][-1]
                dinto_perpkt_bwcost_map[flow][seq][-1].append(tmp_dinto_prevbw + dinto_delta_bitcost)
            # DINTE
            dinte_perflow_pernode_approx[flow][node].append(approx_value)
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

        # Latency measurement accuracy
        if hopidx == hopnum-1:
            eventnum += 1
        if eventnum == packets:
            pint_median_avgre, pint_tail_avgre = get_approx_res(pint_perflow_pernode_approx, perflow_pernode_truth)
            dinto_median_avgre, dinto_tail_avgre = get_approx_res(dinto_perflow_pernode_approx, perflow_pernode_truth)
            dinte_median_avgre, dinte_tail_avgre = get_approx_res(dinte_perflow_pernode_approx, perflow_pernode_truth)
            pint_median_avgre_list.append(pint_median_avgre)
            pint_tail_avgre_list.append(pint_tail_avgre)
            dinto_median_avgre_list.append(dinto_median_avgre)
            dinto_tail_avgre_list.append(dinto_tail_avgre)
            dinte_median_avgre_list.append(dinte_median_avgre)
            dinte_tail_avgre_list.append(dinte_tail_avgre)

            # Reset
            perflow_pernode_truth = {} # {flow, {node, [latency * pktnum]}}
            pint_perflow_pernode_approx = {} # {flow, node, [approx * pktnum]}
            dinto_perflow_pernode_approx = {} # {flow, node, [approx * pktnum]}
            dinte_perflow_pernode_approx = {} # {flow, node, [approx * pktnum]}
            eventnum = 0
f.close()

### Bandwidth cost ###

sum_pint_avgbitcost, sum_dinto_avgbitcost, sum_dinte_avgbitcost = 0, 0, 0

# PINT 
pktnum = 0
for flow, seq_bwcost_map in int_perpkt_bwcost_map.items():
    for seq, runtimes_bwcost_list in seq_bwcost_map.items():
        runtimeidx = 0
        for hop_bwcost_list in runtimes_bwcost_list:
            pktnum += 1
            tmp_hopnum = len(hop_bwcost_list)
            tmp_bitcost = 0
            for i in range(len(hop_bwcost_list)):
                tmp_bitcost += hop_bwcost_list[i]
            sum_int_avgbitcost += (float(tmp_bitcost) / float(tmp_hopnum))
            runtimeidx += 1
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
